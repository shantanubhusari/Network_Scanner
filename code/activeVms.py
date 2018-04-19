#!/usr/bin/env python
from openstack import connection
import json
import os

# Create connection to OpenStack using SDK
conn = connection.Connection(   auth_url="http://10.0.2.11/identity/v3",
                                username="admin", password="shantanu",
                                project_name="admin",
                                project_domain_id="default",
                                user_domain_id="default")

serverList = []
# Fetch network information and Compute information
netObj = conn.network.networks()
for server in conn.compute.servers():
    ipv4 = ""
    ipv4f = ""
    networkName = server.addresses.keys()[0]
    for address in server.addresses.values()[0]:
        if address["OS-EXT-IPS:type"] == "fixed":
            ipv4 = address["addr"]
        elif address["OS-EXT-IPS:type"] == "floating":
            ipv4f = address["addr"]

    for network in netObj:
        if network.name == networkName:
            cmd = "ip netns list | grep "+network.id
            netnamespace = os.popen(cmd).read().strip("\n")

    serverList.append({
                        "instance_name":server.name,
                        "network_name":networkName,
                        "fixed_ip":ipv4,
                        "floating_ip":ipv4f,
                        "status":server.status,
                        "network_namespace": netnamespace
    })

data = {"result" : serverList}
with open("data/activeVms.json", 'w') as jfile:
    json.dump (data, jfile, indent = 2)
