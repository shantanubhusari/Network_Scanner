from flask import Flask
from flask_restful import Resource, Api
from pymongo import *
from netaddr import *
import os
import json

# Connect to Nova API
from keystoneauth1 import loading
from keystoneauth1 import session
from novaclient import client
loader = loading.get_plugin_loader('password')
auth = loader.load_from_options(auth_url="http://10.0.2.11/identity/v3",
                                username="admin", password="shantanu",
                                project_name="admin",
                                project_domain_id="default",
                                user_domain_id="default",
                                project_id="f4828a747f48497c9e19776f8b49e2cc")

app = Flask(__name__)
api = Api(app)

ip_address=''

dbclient = MongoClient(port = 27017)
db = dbclient.ScanData
coll = db.nmapScanData

class DataFetch():
    def getData(self, netns, ip_address):
        data = coll.find({"network_namespace":netns, "fixed_ip":ip_address})
        if data.count() > 0:
            rData = data[0]
            rData.pop('_id')
            return rData
        else:
            return 'null'

# Get result for single IP
class ScanIp(Resource):
    def get(self, netns, ip_address):
        systems = []
        gd = DataFetch()
        system = gd.getData(netns, ip_address)
        if system != "null":
            systems.append(system)
        result = {"systems":systems}
        return result

# Get result for IP range
class ScanRange(Resource):
    def get(self, netns, ip_range):
        systems = []
        gd = DataFetch()

        # Form starting and ending ip-addresses
        net1, net2 = ip_range.split('-')
        ip1 = net1
        ip2 = net1[:-(len(net2))]+"."+net2
        print ip1
        print ip2

        # Form ip address list
        ip_addrs = []
        ip_list = list(iter_iprange(ip1,ip2))
        for ip in ip_list:
            ip_addrs.append(str(ip))

        #Search in the database
        for ip in ip_addrs:
            system = gd.getData(netns, ip)
            if system != "null":
                systems.append(system)
        result = {"systems":systems}
        return result

# Get result for Subnet using CIDR
class ScanNet(Resource):
    def get(self, netns, ip_net, netmask):
        systems = []
        gd = DataFetch()
        ip_addrs = []

        net_addr = ip_net+'/'+netmask
        # Form ip address list
        for ip in IPNetwork(net_addr):
            ip_addrs.append(str(ip))

        #Search in the database
        for ip in ip_addrs:
            system = gd.getData(netns, ip)
            if system != "null":
                systems.append(system)

        result = {"systems":systems}
        return result

# Get information of active VMs
class ActiveVms(Resource):
    def get(self):
        with open('data/activeVms.json') as file1:
            fdata = json.loads(file1.read())
            file1.close()
        return fdata

# Get diagnostics data of active VMs
class DiagnosticsVM(Resource):
    def get(self, netns, ip_addr):
        gd = DataFetch()
        system = gd.getData(netns, ip_addr)
        if system != None:
            inst_name = system["instance_name"]
            sess = session.Session(auth=auth)
            nova = client.Client(2, session=sess)
            for VM in nova.servers.list():
                if VM.name == inst_name and nova.servers.ips(VM).values()[0][0]["addr"] == ip_addr:
                    return nova.servers.diagnostics(VM)[1]

api.add_resource(ScanIp, '/scannet/netns/<netns>/ip/<ip_address>')
api.add_resource(ScanRange, '/scannet/netns/<netns>/iprange/<ip_range>')
api.add_resource(ScanNet, '/scannet/netns/<netns>/ipnet/<ip_net>/<netmask>')
api.add_resource(ActiveVms, '/activevms')
api.add_resource(DiagnosticsVM, '/diagnostics/netns/<netns>/ip/<ip_addr>')

if __name__=="__main__":
    app.run(host='10.0.2.11', port=5050, debug=True)
