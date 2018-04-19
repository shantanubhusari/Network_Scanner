#!/usr/bin/env python

# Import required modules
from flask import Flask
from flask_restful import Resource, Api
import os
import json
from pymongo import *
from datetime import datetime
from time import strftime
import sys, getopt
import xmltodict

# Create database connection
client = MongoClient(port = 27017)
db = client.ScanData
coll = db.nmapScanData

class ScannerNmap():

    #Perform nmap scan
    def scanByNmap(self, netns, ip_address):
        time1 = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        cmd = 'ip netns exec '+netns+' nmap -v0 -A -T4 ' + ip_address + ' -oX data/'+ time1 +'.xml --webxml > /dev/null'
        os.system (cmd)

        # Convert xml to a dictionary object
        with open ('data/'+time1+'.xml', "rb") as f:
            data = xmltodict.parse(f, xml_attribs=True)

            # Find active hosts for parsing the data
            if "host" in data["nmaprun"]:
                if type(data["nmaprun"]["host"]).__name__=="OrderedDict":
                    if data["nmaprun"]["host"]["status"]["@state"]=="up":
                        self.storeInDatabase(netns, data["nmaprun"]["host"], timestamp, time1)
                else:
                    for system in data["nmaprun"]["host"]:
                        if system["status"]["@state"]=="up":
                            self.storeInDatabase(netns, system, timestamp, time1)

        return

    #Store in database
    def storeInDatabase(self, netns, data, timestamp, timeName):
        final = dict()
        cpe = ''
        ipv4f = ''
        netn_name = ''
        inst_name = ''
        if type(data["address"]).__name__=="OrderedDict":
            ipv4=data["address"]["@addr"]
            mac=None
        else:
            ipv4=data["address"][0]["@addr"]
            mac=data["address"][1]["@addr"]

        # Get floating IP address for that machine and perform OpenVAS Scan
        with open('data/activeVms.json') as file1:
            fdata = json.loads(file1.read())
            file1.close()
        for vm in fdata["result"]:
            if vm["fixed_ip"] == ipv4:
                ipv4f = vm["floating_ip"]
                inst_name = vm["instance_name"]
                netn_name = vm["network_name"]
                netnamesp = vm["network_namespace"]
                cmd = "python code/ovaspScan.py "+ipv4f+"-"+timeName+" "+ipv4f+" Y"
                os.system (cmd)

        # Extract running services info
        services = self.extractServices(data, ipv4f)

        # Extract OS info
        if data["os"] != None:
            osinfo = self.extractOsInfo(data)
        else:
            osinfo=[None, None]

        # Create the object to store
        final = {"scantype":"Service and Vulnerability Scan",
                "scantime": timestamp,
                "network_namespace": netns,
                "fixed_ip":ipv4,
                "floating_ip":ipv4f,
                "network_name": netn_name,
                "instance_name": inst_name,
                "network_namespace":netnamesp,
                "mac":mac,
                "osname":osinfo[0],
                "oscpes":osinfo[1],
                "services":services}

        with open ('results/'+ ipv4 +'-jsondump.json', 'w') as outfile:
            json.dump(final,outfile, indent=2)

        #Check if entry already exist, remove if yes to add new
        if coll.find({"ip": ipv4}).count() > 0:
            coll.remove({"ip":ipv4})

        # os.remove("report.xml")
        coll.insert_one(final)

        return

    # Extract running services info
    def extractServices(self, data, ipv4f):
        services = []
        if "port" in data["ports"]:
            if type(data["ports"]["port"]).__name__=="OrderedDict":
                serviceData = self.appendService(data["ports"]["port"], ipv4f)
                services.append(serviceData)
            else:
                for serv in data["ports"]["port"]:
                    serviceData = self.appendService(serv, ipv4f)
                    services.append(serviceData)
            return services

    # To append the information of a service
    def appendService(self, serv, ipv4f):
        cpe = self.isExist(serv["service"], "cpe")
        extrainfo = self.isExist(serv["service"], "@extrainfo")
        product=self.isExist(serv["service"], "@product")

        if "@version" in serv["service"]:
            version = serv["service"]["@version"]
        elif "@ostype" in serv["service"]:
            version = serv["service"]["@ostype"]
        else:
            version = None

        # Parse the information of this port from openVAS report
        vul_info = self.parseOpenvasReport("data/report.xml", ipv4f, serv["@portid"]+"/"+serv["@protocol"])

        rdata = {   "name":serv["service"]["@name"],
                    "port":serv["@portid"],
                    "protocol":serv["@protocol"],
                    "product": product,
                    "version":version,
                    "extrainfo":extrainfo,
                    "cpe": cpe,
                    "vulnerability":vul_info,
                    "state":serv["state"]["@state"]}
        return rdata

    # Parse OpenVAS report to extract required info
    def parseOpenvasReport(self, filename, ip_addr, port_id):
        vul_info = []
        if os.path.isfile('data/report.xml'):
            with open (filename, "rb") as f:
                d = xmltodict.parse(f, xml_attribs=True)
                if self.isExist(d["get_reports_response"]["report"]["report"]["results"], "result"):
                    for result in d["get_reports_response"]["report"]["report"]["results"]["result"]:
                        if (result["host"] == ip_addr and result["port"] == port_id):
                            cvel = result["nvt"]["cve"]
                            cvelist = cvel.split(", ")
                            if cvelist:
                                for cve in cvelist:
                                    if cve != "NOCVE":
                                        vul_info.append({"cvss_score":result["nvt"]["cvss_base"], "cve_ids":cve})
                f.close()
        else:
            vul_info.append({"error":"No Floating ip is assigned or openVAS report file failed to generate"})

        if len(vul_info) == 0:
            vul_info.append({"cvss_score":"0.0", "cve_ids":"NOCVE"})

        return vul_info

    # Extract OS info
    def extractOsInfo(self, data):
        oscpe = []
        osname = []
        if (type(data["os"]["osmatch"]).__name__=="OrderedDict"):
            osname.append(data["os"]["osmatch"]["@name"])
            if type(data["os"]["osmatch"]["osclass"]).__name__=="OrderedDict":
                oscpe.append(data["os"]["osmatch"]["osclass"]["cpe"])
            else:
                for osclass in data["os"]["osmatch"]["osclass"]:
                    oscpe.append(osclass["cpe"])

        elif(type(data["os"]["osmatch"]).__name__=="list"):
            for os in data["os"]["osmatch"]:
                osname.append(os["@name"])
                if type(os["osclass"]).__name__=="OrderedDict":
                    oscpeItem = self.isExist(os["osclass"], "cpe")
                    oscpe.append(oscpeItem)
                else:
                    for osclass in os["osclass"]:
                        oscpe.append(osclass["cpe"])
        return [osname, oscpe]

    # To check if key exists
    def isExist(self, data, key):
        if key in data:
            return data[key]
        else:
            return None

    # To check if list is empty
    def isListEmpty(self, data, key):
        val = []
        if key in data:
            if len(data[key]) == 0:
                return val
            else:
                return data[key]
        else:
            return val

# Import arguments from command line
def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hn:i:", ["help=", "netns=", "ip="])
    except getopt.GetoptError:
        print ("python code/scannerNmap.py -n <network namespace> -i <ip address/ip subnet>")
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print ("python code/scannerNmap.py -n <network namespace> -i <ip address/ip subnet>")
            sys.exit()
        elif opt in ("-i", "--ip"):
            ip_address = arg
        elif opt in ("-n", "--netns"):
            netns = arg

    obj = ScannerNmap()
    obj.scanByNmap(netns, ip_address)

if __name__ == "__main__":
    main(sys.argv[1:])
