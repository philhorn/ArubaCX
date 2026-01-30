import re
from cli import cli

def run():
    # 1. Get the raw text output from the command in your screenshot
    raw_output = cli("show lldp neighbor-info detail")
    
    # 2. Split the output into blocks using the dashed line separator
    # The regex r'-{10,}' looks for 10 or more dashes in a row
    entries = re.split(r'-{10,}', raw_output)
    
    print(f"Processing {len(entries)} LLDP entries...")

    for entry in entries:
        # Skip empty entries (often the first or last split)
        if not entry.strip():
            continue

        # 3. Extract the specific fields shown in your screenshot
        # We use re.search to find the specific keys. 
        # .strip() removes the whitespace padding.
        
        # Find Local Port (e.g., 1/1/48)
        local_port_match = re.search(r"Port\s+:\s+(.+)", entry)
        
        # Find Remote Hostname (e.g., GS...)
        sys_name_match = re.search(r"Neighbor System-Name\s+:\s+(.+)", entry)
        
        # Find Remote Port (e.g., 1/1/46)
        remote_port_match = re.search(r"Neighbor Port-ID\s+:\s+(.+)", entry)

        if local_port_match and sys_name_match and remote_port_match:
            local_port = local_port_match.group(1).strip()
            sys_name = sys_name_match.group(1).strip()
            remote_port = remote_port_match.group(1).strip()

            # 4. Clean up the data for the description label
            # Replace spaces in the hostname with underscores to make it one word
            clean_sys_name = re.sub(r'\s+', '_', sys_name)
            
            # Construct the new description
            new_desc = f"UPLINK_TO_{clean_sys_name}_{remote_port}"
            
            print(f"Match found: {local_port} connects to {clean_sys_name} ({remote_port})")
            
            # 5. Apply the configuration
            try:
                cli("configure terminal")
                cli(f"interface {local_port}")
                cli(f"description {new_desc}")
                cli("exit") # exit interface
                cli("exit") # exit config
            except Exception as e:
                print(f"Error configuring {local_port}: {e}")

# Run the logic
run()
