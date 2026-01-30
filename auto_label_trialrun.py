import re
from cli import cli

def run():
    print(">>> STARTING DRY RUN: No changes will be made <<<")
    
    # 1. Get the raw text output
    # We use the exact same command as the real script
    raw_output = cli("show lldp neighbor-info detail")
    
    # 2. Split entries by the dashed line
    entries = re.split(r'-{10,}', raw_output)
    
    match_count = 0
    
    for entry in entries:
        if not entry.strip():
            continue

        # 3. Extract fields (Same logic as the live script)
        local_port_match = re.search(r"Port\s+:\s+(.+)", entry)
        sys_name_match = re.search(r"Neighbor System-Name\s+:\s+(.+)", entry)
        remote_port_match = re.search(r"Neighbor Port-ID\s+:\s+(.+)", entry)

        if local_port_match and sys_name_match and remote_port_match:
            match_count += 1
            local_port = local_port_match.group(1).strip()
            sys_name = sys_name_match.group(1).strip()
            remote_port = remote_port_match.group(1).strip()

            # 4. Format the Description
            clean_sys_name = re.sub(r'\s+', '_', sys_name)
            clean_remote_port = re.sub(r'[^a-zA-Z0-9/]', '', remote_port_id) # Basic cleaning
            
            # Use the exact same naming convention as your production script
            proposed_desc = f"UPLINK_TO_{clean_sys_name}_{remote_port}"
            
            # 5. REPORT ONLY (No Config)
            print("-" * 40)
            print(f"MATCH FOUND on Interface: {local_port}")
            print(f"  Neighbor:      {sys_name}")
            print(f"  Remote Port:   {remote_port}")
            print(f"  PROPOSED DESC: {proposed_desc}")
            print("-" * 40)

    if match_count == 0:
        print("No valid LLDP neighbors found to label.")
    else:
        print(f"\n>>> DRY RUN COMPLETE: Found {match_count} potential updates. <<<")

# Execute
run()
