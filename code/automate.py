#!/usr/bin/env python

import os
import json

# Run script to scan active VMs
cmd1 = "python code/activeVms.py"
os.system(cmd1)

if os.path.isfile('data/activeVms.json'):
    with open('data/activeVms.json') as file1:
        fdata = json.loads(file1.read())
        file1.close()

    for vm in fdata["result"]:
        ipv4 = vm["fixed_ip"]
        netns = vm["network_namespace"]
        cmd2 = "python code/scanNmap.py -n "+netns+" -i "+ipv4+" > /dev/null"
        os.system(cmd2)
