# -*- coding: utf-8 -*-
Manifest = {
    'Name': 'LLDP_Auto_Labeler',
    'Description': 'Auto-labels interfaces based on LLDP neighbors',
    'Version': '1.0',
    'Author': 'Admin'
}

from aruba_nae.agents.agent import Agent
from aruba_nae.action.cli import ActionCLI
import re

class Agent(Agent):
    def on_agent_create(self):
        # Run every hour (change to 'every 1.minute' for immediate test)
        self.r1 = self.Rule("LLDP_Update")
        self.r1.condition("every 1.minute")
        self.r1.action(self.update_uplinks)

    def update_uplinks(self, event):
        cmd = ActionCLI("show lldp neighbor-info detail")
        output = cmd.execute()
        
        # Split by dashed lines (robust delimiter)
        entries = re.split(r'-{10,}', output)
        
        for entry in entries:
            if not entry.strip(): continue
            
            # Robust Regex for AOS-CX 10.16 Output
            p_m = re.search(r"Port\s+:\s+(.+)", entry)
            s_m = re.search(r"Neighbor System-Name\s+:\s+(.+)", entry)
            r_m = re.search(r"Neighbor Port-ID\s+:\s+(.+)", entry)
            
            if p_m and s_m and r_m:
                l_port = p_m.group(1).strip()
                s_name = s_m.group(1).strip()
                r_port = r_m.group(1).strip()
                
                # Sanitize
                s_name = re.sub(r'\s+', '_', s_name)
                r_port = re.sub(r'[^a-zA-Z0-9/]', '', r_port)
                
                desc = "UPLINK_TO_{}_{}".format(s_name, r_port)
                
                # Execute Config
                # We use a single string with newlines for the command block
                try:
                    cmds = "configure terminal\ninterface {}\ndescription {}\nexit\nexit".format(l_port, desc)
                    ActionCLI(cmds).execute()
                except:
                    pass
