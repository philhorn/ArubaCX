#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
===============================================================
 UserMgmt.py - Unified Netgear M4250 Local User Management Tool
===============================================================

Menu:
  1) Add / Update Users
  2) Delete Users
  3) Audit Users (write single CSV & display)
  4) View Latest Audit (display only)
  5) Change Session Credentials
  6) Change Audit Column Layout
  7) Push Bulk Config to All Switches
  8) Change Default Privilege Level (0,1, or 15, e.g., 15 admin / 1 read-only)
  0) Exit
Core interaction pattern (validated):
  - enable
  - terminal length 0
  - configure terminal (for add/delete)
  - username <name> level <PRIV_LEVEL> password
  - Enter new password:
  - Confirm new password:
  - exit → save                                    (never use 'end' internally)
  - For Bulk Config: we send lines EXACTLY as pasted (in order)

Enhancements:
  - Credential pre-check on ONE reachable switch before the first operation
  - Session credentials are reused (with a notice) until you select “Change Session Credentials”
  - Multi-threaded add/delete/audit/bulk-config
  - Audit display auto-fits columns to terminal width OR forces any N columns you choose
  - Preserves each device 'show users' order (no re-sorting)
  Here's a sample CSV
Floor,,Description,Model,SerialNumber,MAC Address,Switch IP,Hostname
1,snmp-server sysname ,Sw1Descrip,M4250-9G1F-PoE+,SERIAlnumbr1,54:07:7d:11:11:11,10.1.1.1,Hostname1
2,snmp-server sysname ,Sw2Descrip,M4250-9G1F-PoE+,SERIALnumbr2,54:07:7d:11:11:12,10.1.1.2,Hostname2  
"""

# ===========================
#  Standard Libraries
# ===========================
import csv
import glob
import getpass
import logging
import os
import re
import shutil
import socket
import sys
import time
from collections import OrderedDict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ===========================
#  Third-Party
# ===========================
import paramiko

# ===========================
#  Global Configuration
# ===========================
IPS_CSV = "NetgearIPs.csv"          # Must contain column "Switch IP"
IP_COLUMN = "Switch IP"
MAX_WORKERS = 8                     # Parallel devices for add/delete/audit/bulk-config
READ_TICK = 0.05
PROMPT_TIMEOUT = 20
USER_CAP = 6                        # M4250 user limit

# ---- Default privilege level for new/updated local users ----
# Allowed values: 0, 1, 15
PRIV_LEVEL = 15

AUDIT_PREFIX = "netgear_user_audit_"
AUDIT_GLOB = f"{AUDIT_PREFIX}*.csv"

# ---- Audit grid layout control ----
# 0 = auto-fit to terminal width (default)
# Any positive integer N = force that many columns (renderer will clamp to what fits)
GRID_FORCE_COLS = 0

# Credential pre-check settings
PRECHECK_CONNECT_TIMEOUT = 6        # fast fail SSH connect for pre-check
PRECHECK_CMD_TIMEOUT = 8            # waiting for 'show users' during pre-check

# In-session (memory-only) credentials
session_username = None
session_password = None

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

# =====================================================================
#  Low-Level Shell & I/O Utilities
# =====================================================================

def _drain(chan, idle=0.3):
    """Drain shell output until 'idle' seconds pass since last byte."""
    buf, last = "", time.time()
    while True:
        if chan.recv_ready():
            buf += chan.recv(65535).decode(errors='ignore')
            last = time.time()
        else:
            time.sleep(READ_TICK)
        if time.time() - last >= idle:
            break
    return buf

def flush(chan):
    """Flush any pending shell output."""
    _ = _drain(chan, idle=0.4)

def send_line(chan, line, sleep=0.15):
    """Send a command followed by newline; small sleep to let device react."""
    chan.send(line + "\n")
    time.sleep(sleep)

def read_until(chan, patterns, timeout=PROMPT_TIMEOUT):
    """
    Read until a pattern matches or timeout.
    Returns (matched_index, buffer) where matched_index is -1 on timeout.
    """
    buf, start = "", time.time()
    while time.time() - start < timeout:
        if chan.recv_ready():
            buf += chan.recv(65535).decode(errors='ignore')
            for i, pat in enumerate(patterns):
                if re.search(pat, buf, flags=re.I | re.M):
                    return i, buf
        else:
            time.sleep(READ_TICK)
    return -1, buf

def connect_shell(ip, username, password):
    """Open SSH and interactive shell (with host key auto-accept)."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(ip, username=username, password=password,
                look_for_keys=False, allow_agent=False, timeout=15)
    ch = ssh.invoke_shell(width=220, height=3000)
    time.sleep(0.4)
    flush(ch)
    logging.info(f"[{ip}] Connected")
    return ssh, ch

# =====================================================================
#  Mode Controls (EXEC / CONFIG / ENABLE)
# =====================================================================

def enter_enable(chan, ip, pw):
    """Enter privileged EXEC ('#') if not already there."""
    send_line(chan, "")
    out = _drain(chan, idle=0.2)
    if "#" in out:
        logging.info(f"[{ip}] Already in enable mode")
        return

    logging.info(f"[{ip}] Entering enable…")
    send_line(chan, "enable")
    idx, _ = read_until(chan, [r'password:', r'#\s*$'], timeout=8)
    if idx == 0:
        send_line(chan, pw)
        read_until(chan, [r'#\s*$'], timeout=8)

def at_exec(buf):
    """True when at plain '#' and not at '(Config)#'."""
    return bool(re.search(r'(^|\n)[^\n]*#\s*$', buf)
                and not re.search(r'\(Config\)#', buf))

def ensure_exec(chan, ip):
    """Exit out of config submodes until EXEC ('#') is reached."""
    for _ in range(8):
        send_line(chan, "")
        buf = _drain(chan, idle=0.15)
        if at_exec(buf):
            return
        send_line(chan, "exit")
        _drain(chan, idle=0.15)
    logging.info(f"[{ip}] Warning: could not confirm EXEC prompt")

def wait_config(chan):
    """Enter or confirm '(Config)#'."""
    send_line(chan, "configure terminal")
    read_until(chan, [r'\(Config\)#\s*$'], timeout=8)

def set_pager(chan):
    """Disable paging only once; we use 'terminal length 0'."""
    send_line(chan, "terminal length 0")
    flush(chan)

# =====================================================================
#  Audit Helpers
# =====================================================================

def show_users(chan):
    """Return set of usernames from 'show users' (run at EXEC)."""
    flush(chan)
    send_line(chan, "show users")
    _, out = read_until(chan, [r'#\s*$'], timeout=8)
    users = set()
    if not out:
        return users
    for line in out.splitlines():
        m = re.match(r'^([^\s].*?)\s+Privilege-\d+', line.strip())
        if m:
            users.add(m.group(1))
    return users

def parse_show_users_with_priv(chan):
    """Return list of (username, privilege) in the exact order reported by the device."""
    flush(chan)
    send_line(chan, "show users")
    _, out = read_until(chan, [r'#\s*$'], timeout=8)
    users = []
    if not out:
        return users
    for line in out.splitlines():
        m = re.match(r'^([^\s].*?)\s+Privilege-(\d+)', line.strip())
        if m:
            users.append((m.group(1), m.group(2)))
    return users

def user_in_runconf(chan, name):
    """Check if a username appears in running-config (quoted or unquoted)."""
    flush(chan)
    send_line(chan, "show running-config | include ^username")
    _, out = read_until(chan, [r'#\s*$'], timeout=8)
    if not out:
        return False
    return bool(re.search(r'^username\s+"?%s"?\s+' % re.escape(name), out, re.I | re.M))

def user_present(chan, name):
    """Combined presence check using show-users & run-conf."""
    if name in show_users(chan):
        return True
    return user_in_runconf(chan, name)

# --- Inventory helpers (merge from model script) ----------------------

def _inv_pick(text, pattern, flags=re.M):
    """Return the first capture group for pattern, or '' if not found."""
    m = re.search(pattern, text, flags)
    return m.group(1).strip() if m else ''

def parse_show_version_for_inventory(text):
    """
    Extract hostname, model, firmware, mac, serial, bootcode from 'show version' output.
    Also tolerant to minor formatting differences across Netgear M4250-family.
    """
    # Primary fields from 'show version'
    model    = _inv_pick(text, r'^Machine Model.*\s+([A-Za-z0-9\-\+./]+)\s*$')
    firmware = _inv_pick(text, r'^Software Version.*\s+([0-9][0-9A-Za-z.\-]*)\s*$')
    mac      = _inv_pick(text, r'^Burned In MAC Address.*\s+([0-9A-Fa-f:\.\-]{12,})\s*$')
    serial   = _inv_pick(text, r'^Serial Number.*\s+([A-Za-z0-9]+)\s*$')
    bootcode = _inv_pick(text, r'^Bootcode Version.*\s+([0-9A-Za-z.\-]+)\s*$')

    # Normalize MAC to lowercase with ':' separators
    if mac:
        mac = mac.replace('-', ':').lower()

    # Hostname (Netgear: sysName via SNMP)
    #
    # Prefer "snmp-server sysname <value>" from running-config
    sysname = _inv_pick(
        text,
        r'^\s*snmp-server\s+sysname\s+"?([A-Za-z0-9_.\-]+)"?\s*$',
        flags=re.M
    )

    # Fallbacks:
    #   1) explicit 'hostname <value>' (rare on Netgear)
    #   2) last seen prompt token: (SwitchName)# or (SwitchName)(Config)#
    if not sysname:
        sysname = _inv_pick(
            text,
            r'^\s*hostname\s+([A-Za-z0-9_.\-]+)\s*$',
            flags=re.M
        )

    if not sysname:
        # Prompt extraction fallback
        m = re.findall(r'\(([A-Za-z0-9_.\-]+)\)\([A-Za-z0-9 ]*\)#', text)
        if not m:
            m = re.findall(r'\(([A-Za-z0-9_.\-]+)\)#', text)
        if m:
            sysname = m[-1]

    model    = _inv_pick(text, r'^Machine Model.*\s+([A-Za-z0-9\-+./]+)\s*$')
    firmware = _inv_pick(text, r'^Software Version.*\s+([0-9A-Za-z.\-]+)\s*$')
    mac      = _inv_pick(text, r'^Burned In MAC Address.*\s+([0-9A-Fa-f:.]{12,})\s*$')
    serial   = _inv_pick(text, r'^Serial Number.*\s+([A-Za-z0-9]+)\s*$')
    bootcode = _inv_pick(text, r'^Bootcode Version.*\s+([0-9A-Za-z.\-]+)\s*$')

    if mac:
        mac = mac.lower().replace("-", ":")

    return {
        "hostname": sysname or "",
        "model": model or "",
        "firmware": firmware or "",
        "mac": mac or "",
        "serial": serial or "",
        "bootcode": bootcode or "",
    }

def get_device_inventory(chan):
    """
    Run 'show version' and a tiny hostname include to enrich the buffer,
    then parse all inventory fields including hostname.
    """
    flush(chan)
    send_line(chan, "show version")
    _, ver = read_until(chan, [r'#\s*$'], timeout=12)

    # Append one-liner include of hostname (harmless if absent)
    # include hostname/sysname line
    flush(chan)
    send_line(chan, "show running-config \n include ^snmp-server sysname")
    _, host_inc = read_until(chan, [r'#\s*$'], timeout=6)

    combo = (ver or "") + "\n" + (host_inc or "")
    return parse_show_version_for_inventory(combo)

# =====================================================================
#  Add / Update Users (Capacity-Aware)
# =====================================================================

def create_or_update(chan, ip, name, pw, priv_level):
    """
    Creation/update flow (UNQUOTED username form):
      username <name> level <priv_level> password
        -> Enter new password
        -> Confirm new password
    Leaves us in (Config)# for next user.
    """
    send_line(chan, "")
    if not re.search(r'\(Config\)#\s*$', _drain(chan, idle=0.1)):
        wait_config(chan)

    send_line(chan, f"username {name} level {priv_level} password")
    idx, _ = read_until(chan,
                        [r'Enter new password', r'Invalid', r'Incomplete',
                         r'Unrecognized', r'\(Config\)#', r'#\s*$'],
                        timeout=20)
    if idx != 0:
        return False

    send_line(chan, pw)
    idx2, _ = read_until(chan,
                         [r'Confirm new password', r'Invalid', r'Incomplete',
                          r'Unrecognized', r'\(Config\)#', r'#\s*$'],
                         timeout=20)
    if idx2 != 0:
        return False

    send_line(chan, pw)
    _drain(chan, idle=0.3)
    return True

def add_update_flow(ip, chan, ssh_pass, users):
    """
    Add/update users with enforced 6-user cap:
      - Existing users → overwrite password (+ apply current PRIV_LEVEL)
      - New users → create up to available slots
    """
    summary = {"created": [], "updated": [], "skipped_capacity": [], "errors": []}

    enter_enable(chan, ip, ssh_pass)
    set_pager(chan)

    ensure_exec(chan, ip)
    current_set = show_users(chan)
    count = len(current_set)
    available = max(0, USER_CAP - count)

    for user in users:
        name, pw = user['username'], user['password']
        exists_now = user_present(chan, name)

        if exists_now:
            logging.info(f"[{ip}] {name}: updating (level {PRIV_LEVEL})")
            wait_config(chan)
            if create_or_update(chan, ip, name, pw, PRIV_LEVEL):
                summary["updated"].append(name)
            else:
                summary["errors"].append(name)
            continue

        if available <= 0:
            logging.info(f"[{ip}] {name}: skipped (capacity {count}/{USER_CAP})")
            summary["skipped_capacity"].append(name)
            continue

        logging.info(f"[{ip}] {name}: creating (level {PRIV_LEVEL})")
        wait_config(chan)
        if create_or_update(chan, ip, name, pw, PRIV_LEVEL):
            summary["created"].append(name)
            available -= 1
            count += 1
        else:
            summary["errors"].append(name)

    return summary

# =====================================================================
#  Remove Users (Prompt-Safe & Verified)
# =====================================================================

def remove_once(chan, ip, name):
    """Run a single 'no username <name>' in (Config)#."""
    wait_config(chan)
    flush(chan)
    send_line(chan, f"no username {name}")
    _drain(chan, idle=0.2)

def remove_flow(ip, chan, ssh_pass, to_remove):
    """Remove each username; verify via EXEC (show users + run-conf)."""
    summary = {"removed": [], "absent": [], "errors": []}

    enter_enable(chan, ip, ssh_pass)
    set_pager(chan)

    for name in to_remove:
        ensure_exec(chan, ip)
        exists = user_present(chan, name)

        if not exists:
            logging.info(f"[{ip}] {name}: not present → skipped")
            summary["absent"].append(name)
            continue

        logging.info(f"[{ip}] Removing {name}…")
        remove_once(chan, ip, name)

        ensure_exec(chan, ip)
        still = user_present(chan, name)

        if still:
            logging.info(f"[{ip}] {name}: still present → retrying")
            remove_once(chan, ip, name)
            ensure_exec(chan, ip)
            still = user_present(chan, name)

        if still:
            summary["errors"].append(name)
            logging.info(f"[{ip}] {name}: FAILED to remove")
        else:
            summary["removed"].append(name)
            logging.info(f"[{ip}] {name}: removed")

    return summary

# =====================================================================
#  Save Config (exit → save)
# =====================================================================

def save_config(chan, ip):
    """Back out to EXEC with 'exit' and then 'save' once."""
    ensure_exec(chan, ip)
    send_line(chan, "save")
    idx, _ = read_until(chan,
                        [r'Are you sure.*\(y/n\)', r'Configuration Saved', r'#\s*$'],
                        timeout=20)
    if idx == 0:
        send_line(chan, "y")
        read_until(chan, [r'Configuration Saved', r'#\s*$'], timeout=25)

# =====================================================================
#  Audit (Parallel), CSV Write, and Display
# =====================================================================

def audit_device(ip, ssh_user, ssh_pass):
    """
    Worker: return (ip, users, inv, err)
      - users: list[(username, privilege)] preserving device order
      - inv:   dict(hostname, model, firmware, mac, serial, bootcode)
    """
    try:
        ssh, ch = connect_shell(ip, ssh_user, ssh_pass)
        enter_enable(ch, ip, ssh_pass)
        set_pager(ch)
        ensure_exec(ch, ip)

        # Collect users (as before)
        users = parse_show_users_with_priv(ch)  # preserves reported order

        # Collect model/firmware/mac/serial/bootcode
        inv = get_device_inventory(ch)

        ch.close(); ssh.close()
        return (ip, users, inv, None)
    except Exception as e:
        return (ip, [], {"hostname":"", "model":"", "firmware":"", "mac":"", "serial":"", "bootcode":""}, str(e))

def audit_flow(ips, ssh_user, ssh_pass):
    """
    Parallel audit across devices:
      - write CSV: netgear_user_audit_YYYYMMDD_HHMMSS.csv
        Columns: SwitchIP, Model, Firmware, MAC, Serial, Bootcode, Username, Privilege
      - display results as before (grid renderer unchanged)
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_csv = f"{AUDIT_PREFIX}{ts}.csv"

    # Run the per-device workers
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(lambda ip: audit_device(ip, ssh_user, ssh_pass), ips))

    # Unpack into maps for display + write rows
    per_switch = OrderedDict()
    rows = []
    ip_to_users = {ip: users for (ip, users, inv, err) in results}
    ip_to_inv   = {ip: inv   for (ip, users, inv, err) in results}
    ip_to_err   = {ip: err   for (ip, users, inv, err) in results}

    for ip in ips:
        users = ip_to_users.get(ip, [])
        inv   = ip_to_inv.get(ip, {"hostname":"", "model":"", "firmware":"", "mac":"", "serial":"", "bootcode":""})
        err   = ip_to_err.get(ip, None)

        if err:
            logging.warning(f"[{ip}] ERROR: {err}")

        # Keep display map identical to before (only usernames/privileges)
        per_switch[ip] = users

        # For CSV: emit one row per user, carrying inventory columns
        # If a device has no users, we intentionally skip rows (unchanged behavior);
        # let me know if you'd like one row with blank user to still capture inventory.
        for (u, p) in users:
            rows.append([
                ip, inv.get("hostname",""), inv.get("model",""), inv.get("firmware",""), inv.get("mac",""),
                inv.get("serial",""), inv.get("bootcode",""),
                u, p
            ])

    # Write CSV with the expanded header
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["SwitchIP", "SysName", "Model", "Firmware", "MAC", "Serial", "Bootcode", "Username", "Privilege"])
        w.writerows(rows)

    print(f"\nAudit written to: {out_csv}\n")

    # On-screen grid stays exactly as your current renderer expects
    display_audit_map(per_switch, ip_to_inv)
    return out_csv

# ---- Read/View Latest Audit CSV ----

def latest_audit_path():
    """Return newest netgear_user_audit_*.csv or None."""
    candidates = glob.glob(AUDIT_GLOB)
    if not candidates:
        return None
    candidates.sort(key=lambda p: os.path.getmtime(p), reverse=True)
    return candidates[0]

def read_audit_csv(path):
    """
    Returns:
      per_switch: OrderedDict[IP] -> list[(user, priv)]
      ip_to_inv : dict[IP] -> {hostname, model, firmware, mac, serial, bootcode}
    """
    per_switch = OrderedDict()
    ip_to_inv = {}

    with open(path, "r", encoding="utf-8") as f:
        rdr = csv.DictReader(f)
        for row in rdr:
            ip   = (row.get("SwitchIP") or "").strip()
            user = (row.get("Username") or "").strip()
            priv = (row.get("Privilege") or "").strip()

            if ip not in per_switch:
                per_switch[ip] = []

            if user:
                per_switch[ip].append((user, priv))

            if ip not in ip_to_inv:
                ip_to_inv[ip] = {
                    "hostname": (row.get("SysName") or "").strip(),
                    "model":    (row.get("Model") or "").strip(),
                    "firmware": (row.get("Firmware") or "").strip(),
                    "mac":      (row.get("MAC") or "").strip(),
                    "serial":   (row.get("Serial") or "").strip(),
                    "bootcode": (row.get("Bootcode") or "").strip(),
                }

    return per_switch, ip_to_inv

# =====================================================================
#  Audit Display (Auto-Fit or Forced Multi-Column Grid)
# =====================================================================

def display_audit_map(per_switch_map, ip_to_inv=None):
    """
    Render all switches in a compact multi-column grid.

    Box content per switch:
      <SysName or '(no sysName)'>
      IP: <ip>
      FWv#: <firmware>
      Boot: <bootcode>
      S/N#: <serial>
      MAC#: <mac>
      <username> <priv>
      ...

    Layout:
      - Auto-fit to terminal width, or respect GRID_FORCE_COLS
      - Preserve device-reported user order
    """
    ip_to_inv = ip_to_inv or {}

    if not per_switch_map:
        print("(no audit data)\n")
        return

    boxes = []
    max_width = 14

    for ip, entries in per_switch_map.items():
        inv = ip_to_inv.get(ip, {})
        name = inv.get("hostname", "") or "(no sysName)"

        lines = []
        lines.append(name)
        lines.append(f"IP: {ip}")
        lines.append(f"FWv#: {inv.get('firmware','')}")
        lines.append(f"Boot: {inv.get('bootcode','')}")
        lines.append(f"S/N#: {inv.get('serial','')}")
        lines.append(f"MAC#: {inv.get('mac','')}")

        for (u, p) in entries:
            lines.append(f"{u} {p}")

        boxes.append(lines)
        max_width = max(max_width, max(len(x) for x in lines))

    # Column layout
    term_cols = shutil.get_terminal_size(fallback=(120, 24)).columns
    col_width = max_width + 2
    gap = 3
    max_fit = max(1, (term_cols + gap) // (col_width + gap))
    cols = GRID_FORCE_COLS if (isinstance(GRID_FORCE_COLS, int) and GRID_FORCE_COLS > 0) else max_fit
    cols = max(1, min(cols, max_fit))

    def pad(s):
        return s + " " * max(0, col_width - len(s))

    # Print in rows
    for base in range(0, len(boxes), cols):
        row = boxes[base:base+cols]
        max_lines = max(len(b) for b in row)
        for i in range(max_lines):
            parts = []
            for b in row:
                txt = b[i] if i < len(b) else ""
                parts.append(pad(txt))
            print((" " * gap).join(parts))
        print()

# =====================================================================
#  Credential Pre-Check (Single Device Sanity Test)
# =====================================================================

def try_ssh_banner(ip, port=22, timeout=2.5) -> bool:
    """Quick TCP probe to see if SSH is reachable before Paramiko connect."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

def first_reachable_ip(ips):
    """Return the first IP that responds on TCP/22; fallback to first entry."""
    for ip in ips:
        if try_ssh_banner(ip):
            return ip
    return ips[0] if ips else None

def credential_precheck(ip, username, password) -> bool:
    """
    Low-cost verification on ONE device:
      - SSH connect (short timeout)
      - enter enable if needed
      - terminal length 0
      - show users (ensure we can read '#')
    Returns True on success, False otherwise.
    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password,
                    look_for_keys=False, allow_agent=False,
                    timeout=PRECHECK_CONNECT_TIMEOUT)
        ch = ssh.invoke_shell(width=160, height=2000)
        time.sleep(0.3)

        _ = _drain(ch, idle=0.15)
        ch.send('\n'); time.sleep(0.15); _ = _drain(ch, idle=0.15)
        ch.send('enable\n'); time.sleep(0.2)
        idx, _ = read_until(ch, [r'password:', r'#\s*$'], timeout=5)
        if idx == 0:
            ch.send(password + '\n'); time.sleep(0.2)
            _ = read_until(ch, [r'#\s*$'], timeout=5)

        ch.send('terminal length 0\n'); time.sleep(0.15); _ = _drain(ch, idle=0.1)
        ch.send('show users\n'); time.sleep(0.15)
        idx2, _ = read_until(ch, [r'#\s*$'], timeout=PRECHECK_CMD_TIMEOUT)

        ch.close(); ssh.close()
        return idx2 != -1
    except Exception:
        return False

def prompt_creds_with_precheck(ips):
    """
    Ask for creds → pre-check on a single reachable switch → proceed or retry.
    Returns (username, password) or (None, None) if cancelled.
    """
    if not ips:
        print("No target IPs found.")
        return None, None

    test_ip = first_reachable_ip(ips)
    if not test_ip:
        print("No reachable devices for precheck.")
        return None, None

    while True:
        user = input("SSH/admin username: ").strip()
        pw   = getpass.getpass("SSH/admin password: ")

        print(f"\nPre-checking credentials on {test_ip} …")
        ok = credential_precheck(test_ip, user, pw)
        if ok:
            print("✅ Credentials verified. Proceeding with all devices.\n")
            return user, pw

        print("❌ Credentials failed on the precheck device.")
        ans = input("Try again? [Y/n]: ").strip().lower()
        if ans == 'n':
            return None, None

def get_or_prompt_session_creds(ips):
    """
    Return (username, password) using in-session credentials if present;
    otherwise run the pre-check loop and store successful creds in memory.
    """
    global session_username, session_password
    if session_username and session_password:
        print("Reusing session credentials …")
        return session_username, session_password

    user, pw = prompt_creds_with_precheck(ips)
    if user and pw:
        session_username, session_password = user, pw
    return user, pw

def change_session_creds(ips):
    """
    Force the user to re-enter credentials and pre-check them.
    If successful, replace the in-session credentials.
    """
    global session_username, session_password
    print("\nChange session credentials:")
    user, pw = prompt_creds_with_precheck(ips)
    if user and pw:
        session_username, session_password = user, pw
        print("Session credentials updated.\n")
    else:
        print("Credentials unchanged.\n")

# =====================================================================
#  BULK CONFIG (NEW) - COMPLETE REPLACEMENT
# =====================================================================

from concurrent.futures import ThreadPoolExecutor

def prompt_bulk_config_lines():
    """
    Prompt the operator to paste multi-line config to be pushed
    inside 'configure terminal'. Finish with a single line 'EOF'.
    Empty lines and lines starting with '#' are ignored.

    NOTE: Do NOT include 'end', 'save', 'y', or 'write memory confirm'.
    The tool will always run those to persist config safely.
    """
    print("""
Paste the config lines to send to ALL switches (inside config mode).
Finish by entering a single line containing: EOF

Example (you just paste the intended config lines):
clock summer-time recurring USA offset 60 zone "CST"
clock timezone -6 minutes 0 zone "CST"
  EOF
""")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "EOF":
            break
        if not line.strip():
            continue
        if line.lstrip().startswith("#"):
            continue
        lines.append(line.rstrip())
    return lines

def _wait_for_prompt(chan, timeout=15):
    """
    Wait for a recognizable prompt or a typical confirmation.
    Returns (idx, out) where idx is which pattern matched.
    """
    return read_until(
        chan,
        [
            r'Are you sure.*\(y/n\)',                  # 0 confirm
            r'\(y/n\)\s*$',                            # 1 generic (y/n)
            r'#\s*$',                                  # 2 exec prompt
            r'\(Config\)#\s*$',                        # 3 config prompt
            r'Save configuration changes\?.*\(y/n\)\s*$',  # 4 save confirm
            r'Proceed.*\(y/n\)\s*$',                   # 5 proceed confirm
        ],
        timeout=timeout
    )

def send_and_auto_confirm(chan, cmd, timeout=15):
    """
    Send a command and auto-confirm common (y/n) prompts with 'y'.
    Returns (idx, out) from the last read_until.
    """
    send_line(chan, cmd)
    idx, out = _wait_for_prompt(chan, timeout=timeout)

    # If we hit any (y/n) style confirmation, answer 'y' and wait for prompt again
    if idx in (0, 1, 4, 5):
        send_line(chan, "y")
        idx, out = read_until(chan, [r'#\s*$', r'\(Config\)#\s*$'], timeout=timeout)

    # Small drain to stabilize channel output
    _drain(chan, idle=0.2)
    return idx, out


def _ensure_config_mode(chan, ip):
    """
    Make sure we are in enable and in configure terminal.
    """
    # Ensure we're in enable; set pager once
    enter_enable(chan, ip, session_password)
    set_pager(chan)

    # Enter config terminal
    send_and_auto_confirm(chan, "configure terminal", timeout=10)
    # We should now be at (Config)#


def _exit_config_and_save(chan):
    """
    Deterministic persistence flow:
      1) end
      2) save  -> auto 'y' if prompted
      3) write memory confirm (accepted by many Netgear families)
    """
    # Exit config mode
    send_and_auto_confirm(chan, "end", timeout=10)

    # Primary save path
    send_and_auto_confirm(chan, "save", timeout=20)

    # Secondary/alternate path; harmless if unsupported
    send_line(chan, "write memory confirm")
    read_until(chan, [r'#\s*$'], timeout=10)
    _drain(chan, idle=0.2)


def _best_effort_logout(chan):
    """
    Try to close shell cleanly; ignore errors.
    """
    for cmd in ("exit", "logout"):
        try:
            send_line(chan, cmd)
            read_until(
                chan,
                [r'closed', r'#\s*$', r'\$ \s*$', r'login:\s*$'],
                timeout=5
            )
        except Exception:
            pass


def run_bulk_commands(chan, ip, commands):
    """
    Enforce the standard flow:
      - enable
      - configure terminal
      - send user lines (as-is)
      - end + save (y) + write memory confirm
      - logout
    Auto-confirms common prompts.
    """
    # 1) Enter enable + config
    _ensure_config_mode(chan, ip)

    # 2) Run user-supplied commands exactly as provided (inside config mode)
    for raw in commands:
        cmd = raw.strip()
        if not cmd:
            continue
        send_and_auto_confirm(chan, cmd, timeout=15)

    # 3) Exit config and save
    _exit_config_and_save(chan)

    # 4) Best-effort logout (shell may already close after save on some boxes)
    _best_effort_logout(chan)

    return True


def bulk_config_device(ip, ssh_user, ssh_pass, commands):
    """
    Device worker: connect, run all commands, return summary for this device.
    """
    ssh, ch = None, None
    try:
        ssh, ch = connect_shell(ip, ssh_user, ssh_pass)
        ok = run_bulk_commands(ch, ip, commands)
        try:
            ch.close()
        except Exception:
            pass
        try:
            ssh.close()
        except Exception:
            pass
        return {"ip": ip, "ok": ok, "error": None}
    except Exception as e:
        # Try to close if something blew up mid-flight
        try:
            if ch:
                ch.close()
        except Exception:
            pass
        try:
            if ssh:
                ssh.close()
        except Exception:
            pass
        return {"ip": ip, "ok": False, "error": str(e)}


def do_bulk_config(ips):
    """
    Orchestrate bulk config:
      - reuse / pre-check session creds
      - collect commands (config-mode only)
      - fan out in threads across devices
      - always persist changes (end/save/y/write memory confirm)
    """
    ssh_user, ssh_pass = get_or_prompt_session_creds(ips)
    if not ssh_user:
        print("Operation cancelled.\n")
        return

    commands = prompt_bulk_config_lines()
    if not commands:
        print("No commands provided. Cancelled.\n")
        return

    print("\nPushing config to all switches…\n")
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(
            lambda ip: bulk_config_device(ip, ssh_user, ssh_pass, commands),
            ips
        ))

    # Summary
    print("\n=== BULK CONFIG SUMMARY ===")
    ok_count = err_count = 0
    for r in results:
        if r["ok"] and not r["error"]:
            ok_count += 1
            print(f"{r['ip']}: OK")
        else:
            err_count += 1
            print(f"{r['ip']}: ERROR - {r['error']}")
    print(f"\nTotals: success={ok_count}, errors={err_count}\n")

# =====================================================================
#  Device-Level Wrappers (thread targets)
# =====================================================================

def add_update_device(ip, ssh_user, ssh_pass, users):
    ssh, ch = None, None
    try:
        ssh, ch = connect_shell(ip, ssh_user, ssh_pass)
        result = add_update_flow(ip, ch, ssh_pass, users)
        save_config(ch, ip)
        ch.close(); ssh.close()
        result["ip"] = ip
        return result
    except Exception as e:
        return {"ip": ip, "created": [], "updated": [], "skipped_capacity": [], "errors": [str(e)]}

def remove_device(ip, ssh_user, ssh_pass, to_remove):
    ssh, ch = None, None
    try:
        ssh, ch = connect_shell(ip, ssh_user, ssh_pass)
        result = remove_flow(ip, ch, ssh_pass, to_remove)
        save_config(ch, ip)
        ch.close(); ssh.close()
        result["ip"] = ip
        return result
    except Exception as e:
        return {"ip": ip, "removed": [], "absent": [], "errors": [str(e)]}

# =====================================================================
#  Audit Convenience
# =====================================================================

def do_audit_now(ips, ssh_user, ssh_pass):
    """Run an audit (parallel), write CSV, and immediately display the grid."""
    path = audit_flow(ips, ssh_user, ssh_pass)
    return path

def view_latest_audit():
    """Load newest audit CSV and display the grid."""
    path = latest_audit_path()
    if not path:
        print("\n(No prior audit CSVs found.)\n")
        return
    data, ip_to_inv = read_audit_csv(path)
    print(f"\nLatest audit file: {path}\n")
    display_audit_map(data, ip_to_inv)

# =====================================================================
#  CSV / Input Prompts
# =====================================================================

def load_ips():
    ips = []
    with open(IPS_CSV, "r", newline="") as f:
        for row in csv.DictReader(f):
            ip = (row.get(IP_COLUMN) or "").strip()
            if ip and ip.lower() != "not found":
                ips.append(ip)
    return ips

def prompt_users_add():
    users = []
    print(f"\nEnter users to add/update (blank username to finish). "
          f"Current default privilege level: {PRIV_LEVEL}")
    while True:
        u = input("  Username: ").strip()
        if not u:
            break
        p1 = getpass.getpass("    Password: ")
        p2 = getpass.getpass("    Confirm : ")
        if p1 != p2:
            print("    Passwords do not match.")
            continue
        users.append({"username": u, "password": p1})
    return users

def prompt_users_delete():
    names = []
    print("\nEnter users to delete (blank to finish):")
    while True:
        u = input("  Username: ").strip()
        if not u:
            break
        names.append(u)
    return names

# =====================================================================
#  Layout Control
# =====================================================================

def change_audit_layout():
    """
    Menu option that lets the user choose the number of audit columns:
    0 (auto-fit), or any positive integer N to force exactly N columns
    (renderer will clamp to what actually fits in the current terminal).
    """
    global GRID_FORCE_COLS

    print("""
Change Audit Column Layout
--------------------------
0  = Auto-fit (default)
N  = Force N columns (any positive integer)
""")

    while True:
        val = input("Choose layout (0 or any positive integer): ").strip()
        if val.isdigit():
            n = int(val)
            if n >= 0:
                GRID_FORCE_COLS = n
                print(f"Audit column layout set to {GRID_FORCE_COLS} (0 = auto-fit).\n")
                return
        print("Invalid selection. Enter 0 or any positive integer (e.g., 4, 6, 10, 12).")

# =====================================================================
#  Privilege Level Control (Menu 0)
# =====================================================================

def change_priv_level():
    """
    Set the default privilege level used for Add/Update.
    Allowed values: 0, 1, or 15.

      15 = admin/full
       1 = read-only
       0 = no-priv / custom minimal (device-specific)
    """
    global PRIV_LEVEL
    print(f"\nChange Default Privilege Level (current: {PRIV_LEVEL})")
    print("Allowed values: 15 (admin), 1 (read-only), 0 (minimal)\n")

    while True:
        val = input("Enter new level (0, 1, or 15): ").strip()
        # Accept exact strings only; no other integers
        if val in ("0", "1", "15"):
            PRIV_LEVEL = int(val)
            print(f"Default privilege level set to {PRIV_LEVEL}.\n")
            return
        print("Invalid entry. Please enter exactly 0, 1, or 15.")

# =====================================================================
#  Menu / Main
# =====================================================================

def main():
    ips = load_ips()
    if not ips:
        print(f"No valid IPs found in '{IPS_CSV}' column '{IP_COLUMN}'.")
        return

    while True:
        print(f"""
==========================
 Netgear User Management
==========================
 Current default privilege level: {PRIV_LEVEL}

 1) Add / Update Users
 2) Delete Users
 3) Audit Users and Switches (CSV plus display)
 4) View Latest Audit (display only)
 5) Push Bulk Config to All Switches
 6) Change Audit Column Layout
 7) Change Session Credentials
 8) Change Default Privilege Level
 0) Exit
""")

        choice = input("Select an option: ").strip()

        # -------- EXIT --------
        if choice == "0":
            print("Goodbye.")
            return

        # -------- 1) Add/Update Users --------
        elif choice == "1":
            ssh_user, ssh_pass = get_or_prompt_session_creds(ips)
            if not ssh_user:
                print("Operation cancelled.\n")
                continue
            users = prompt_users_add()
            if not users:
                print("No users entered.")
                continue

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                results = list(pool.map(
                    lambda ip: add_update_device(ip, ssh_user, ssh_pass, users),
                    ips
                ))

            print("\n=== SUMMARY ===")
            for r in results:
                print(f"{r['ip']}: created={len(r['created'])}, "f"updated={len(r['updated'])}, "f"skipped_capacity={len(r['skipped_capacity'])}, "
                      f"errors={len(r['errors'])}")

        # -------- 2) Delete Users --------
        elif choice == "2":
            ssh_user, ssh_pass = get_or_prompt_session_creds(ips)
            if not ssh_user:
                print("Operation cancelled.\n")
                continue
            to_remove = prompt_users_delete()
            if not to_remove:
                print("Nothing to delete.")
                continue

            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                results = list(pool.map(
                    lambda ip: remove_device(ip, ssh_user, ssh_pass, to_remove),
                    ips
                ))

            print("\n=== SUMMARY ===")
            for r in results:
                print(f"{r['ip']}: removed={len(r['removed'])}, "
                      f"absent={len(r['absent'])}, "
                      f"errors={len(r['errors'])}")

        # -------- 3) Audit Users and Switches --------
        elif choice == "3":
            ssh_user, ssh_pass = get_or_prompt_session_creds(ips)
            if not ssh_user:
                print("Operation cancelled.\n")
                continue
            do_audit_now(ips, ssh_user, ssh_pass)

        # -------- 4) View Latest Audit --------
        elif choice == "4":
            view_latest_audit()

        # -------- 5) Bulk Config --------
        elif choice == "5":
            do_bulk_config(ips)

        # -------- 6) Change Audit Layout --------
        elif choice == "6":
            change_audit_layout()

        # -------- 7) Change Session Credentials --------
        elif choice == "7":
            change_session_creds(ips)

        # -------- 8) Change Default Privilege Level --------
        elif choice == "8":
            change_priv_level()

        # -------- INVALID --------
        else:
            print("Invalid choice.")
            continue
# =====================================================================
#  Entry Point
# =====================================================================

if __name__ == "__main__":
    main()
