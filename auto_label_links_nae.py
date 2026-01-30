# -*- coding: utf-8 -*-
#
# Manifest={
#     "Name": "LLDP Auto Labeler",
#     "Description": "Updates interface descriptions based on LLDP neighbors. Checks every hour.",
#     "Version": "1.0",
#     "Author": "Admin"
# }

from aruba_nae.agents.agent import Agent
from aruba_nae.action.cli import ActionCLI
import re

class Agent(Agent):
    def on_agent_create(self):
        # Schedule the check to run every 1 hour
        # You can change this to 'every 1.minute' for testing
        self.r1 = self.Rule("LLDP_Update_Timer")
        self.r1.condition("every 1.hour")
        self.r1.action(self.update_uplinks)

    def update_uplinks(self, event):
        self.logger.info("Starting LLDP Description Update...")
        
        # 1. Get LLDP Info
        # We use the 'detail' view to ensure we get full system names
        cmd = ActionCLI("show lldp neighbor-info detail")
        output = cmd.execute()
        
        # 2. Split output by dashed lines
        entries = re.split(r'-{10,}', output)
        
        for entry in entries:
            if not entry.strip():
                continue

            # 3. Regex Match (Based on your screenshot)
            # Looks for: Port, Neighbor System-Name, Neighbor Port-ID
            local_port_match = re.search(r"Port\s+:\s+(.+)", entry)
            sys_name_match = re.search(r"Neighbor System-Name\s+:\s+(.+)", entry)
            remote_port_match = re.search(r"Neighbor Port-ID\s+:\s+(.+)", entry)

            if local_port_match and sys_name_match and remote_port_match:
                local_port = local_port_match.group(1).strip()
                sys_name = sys_name_match.group(1).strip()
                remote_port = remote_port_match.group(1).strip()

                # Clean up the strings (replace spaces with underscores)
                clean_sys_name = re.sub(r'\s+', '_', sys_name)
                clean_remote_port = re.sub(r'[^a-zA-Z0-9/]', '', remote_port)
                
                # Define the new description
                new_desc = "UPLINK_TO_{}_{}".format(clean_sys_name, clean_remote_port)

                # 4. Apply Configuration
                # NAE allows executing configuration commands directly
                cmds = [
                    "configure terminal",
                    "interface {}".format(local_port),
                    "description {}".format(new_desc),
                    "exit",
                    "exit"
                ]
                
                try:
                    # Execute the config change
                    ActionCLI("\n".join(cmds)).execute()
                    self.logger.info("Updated {}: {}".format(local_port, new_desc))
                except Exception as e:
                    self.logger.error("Failed to update {}: {}".format(local_port, str(e)))
