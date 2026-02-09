import csv
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed

# Read IPs from CSV
ip_list = []
with open("C:\\Support\\ip_list.csv", mode="r", encoding="utf-8-sig", newline='') as csvfile:
    reader = csv.DictReader(csvfile)
    print(f"CSV headers:", reader.fieldnames)
    for row in reader:
        ip_list.append(row["IPAddress"])

# Determine ping command based on OS
param = "-n" if platform.system().lower() == "windows" else "-c"

# Function to ping a single IP
def ping_ip(ip):
    try:
        result = subprocess.run(["ping", param, "1", ip], stdout=subprocess.DEVNULL)
        if result.returncode != 0:
            print(f"❌ No response from {ip}")
            return ip
        else:
            print(f"✅ Responded: {ip}")
            return None
    except Exception as e:
        print(f"Error pinging {ip}: {e}")
        return ip

# Use ThreadPoolExecutor to ping IPs concurrently
failed_ips = []
with ThreadPoolExecutor(max_workers=50) as executor:  # Adjust max_workers as needed
    futures = {executor.submit(ping_ip, ip): ip for ip in ip_list}
    for future in as_completed(futures):
        result = future.result()
        if result:
            failed_ips.append(result)

# Save failed IPs
with open("C:\\Support\\failed_ips.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Unreachable IPs"])
    for ip in failed_ips:
        writer.writerow([ip])

print("\nDone. Failed IPs saved to 'failed_ips.csv'.")

