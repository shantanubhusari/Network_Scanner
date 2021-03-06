# Stinger - Network Scanner as a Service

Youtube Link for Demo:
 - https://youtu.be/hzyPjB0sF8M

Following are the dependencies and required modules
 - Install and set up Openstack environment. Create the topology.
 - Install and set up MongoDB server, OpenVas.
 - Install required modules : `$ sudo pip install -r code/requirements.txt`
 - Your working directory should be the main project directory for codes to work successfully

Run MongoDB server before running main scripts

Perform following steps before running Nmap and Vulnerability scans:
 - Download openrc.sh file from devstack dashboard. Save it in a directory you desire.
 - Acquire root shell : `$ sudo -s`
 - source oprnrc file : `$ source openrc.sh` - This step will set environment variables required for authentication to use openstack APIs

Steps to perform scans:
 - Generate the database of active VMs using following command: `$ python code/activeVms.py`
 - To scan the network use scanner script as following:
      `$ python code/scannerNmap.py -n <netns> -i <ip_address/range/subnet>`
 - Or to run as a background process:
      `$ python code/scannerNmap.py -n <netns> -i <ip address/range/subnet> &`
 - This will populate the database with entries
 - Above steps can be automated using `$ python code/automate.py` for active VMs

Run Restful service as:
 - `$ sudo python code/scannerApis.py`

To fetch the data, following are the APIs:
 - `http://<machine-ip>:5050/scannet/netns/<netns>/ip/<ip_address>`
 	-> To fetch information for a single IP Address (ex, 192.168.1.5)

 - `http://<machine-ip>:5050/scannet/netns/<netns>/iprange/<ip_range>`
 	-> To fetch information for a range of ip addresses (ex, 192.168.1.5-10)

 - `http://<machine-ip>:5050/scannet/netns/<netns>/ipnet/<ip_net>/<netmask>`
 	-> To fetch information for a subnet using CIDR (ex, 192.168.1.0/24)

 - `http://<machine-ip>:5050/activevms`
  -> To get the list of active VMs

 - `http://<machine-ip>:5050/diagnostics/netns/<netns>/ip/<ip_addr>`
  -> To get diagnostics data of given ip address acquired from Nova Apis
