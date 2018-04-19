#!/usr/bin/env python

import sys
import subprocess
import argparse
import xml.etree.ElementTree as ET
from time import sleep

parser = argparse.ArgumentParser()
parser.add_argument("Target_name", help="Name for the taget to be created")
parser.add_argument("Hosts", help="IP Address of the hosts")
parser.add_argument("Override", help="Override existing Target is present.(Y/n) Y-> overwrite n-> use existing target values")
parser.add_argument("-t", "--scan_type", default = int("2"), help="0. Discovery \n1. empty\n2. Full and fast\n3. Full and fast ultimate\n4. Full and very deep\n5. Full and very deep ultimate\n6. Host Discovery\n7. System Discovery")
args = parser.parse_args()

f1 = open("data/report.xml", "w")

user = "admin"

password = "admin"

scan_ids = ["8715c877-47a0-438d-98a3-27c7a6ab2196", "085569ce-73ed-11df-83c3-002264764cea", "daba56c8-73ec-11df-a475-002264764cea",
"698f691e-7489-11df-9d8c-002264764cea", "708f25c4-7489-11df-8094-002264764cea",
"74db13d6-7489-11df-91b9-002264764cea", "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
"bbca7412-a950-11e3-9109-406186ea4fc5"]

#create_target
proc0 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '--xml=<create_target><name>'+args.Target_name+'</name><hosts>'+args.Hosts+'</hosts></create_target>'], stdout=subprocess.PIPE)

for line in proc0.stdout.readlines():
	root = ET.fromstring(line)

if root.attrib['status_text'] == "Target exists already":
	#check targets
	proc1 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '-T'], stdout=subprocess.PIPE)
	for line in proc1.stdout.readlines():
		tmp = line.split()
		print tmp
		if tmp[1] == args.Target_name:
			if args.Override in ("y", "Y", "yes", "Yes"):
				#delete target
				print tmp[0]
				proc2 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '-iX', '<delete_target target_id="'+tmp[0]+'"/>'], stdout=subprocess.PIPE)
				for line in proc2.stdout.readlines():
					print "line is ", line
					root = ET.fromstring(line)
					print root.attrib['status_text']
				if root.attrib['status_text'] == "OK":
					pass
				else:
					print "error. Try a different name."
					sys.exit()
				#create target
				proc0 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '--xml=<create_target><name>'+args.Target_name+'</name><hosts>'+args.Hosts+'</hosts></create_target>'], stdout=subprocess.PIPE)
				for line in proc0.stdout.readlines():
					root = ET.fromstring(line)
					target_id = root.attrib['id']
					print "Target created with id=", target_id
			else:
				target_id = tmp[0]
				print "Target created with id=", target_id

else:
	target_id = root.attrib['id']
	print "Target created with id=", target_id

#create a task
proc3 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '--xml=<create_task><name>'+args.Target_name+' -'+str(args.scan_type)+'</name><config id="'+scan_ids[int(args.scan_type)]+'"/><target id="'+target_id+'"/></create_task>'], stdout=subprocess.PIPE)

for line in proc3.stdout.readlines():
	root=ET.fromstring(line)

if root.attrib['status_text'] == "OK, resource created":
	task_id = root.attrib['id']
	print "Task created with id=", task_id
else:
	print "error in creating task. Exiting"
	sys.exit()

#start scanning process
proc4 = subprocess.Popen(['sudo', 'omp', '-u', user, '-w', password, '--xml=<start_task task_id="'+task_id+'"/>'], stdout=subprocess.PIPE)

for line in proc4.stdout.readlines():
	print line
	root=ET.fromstring(line)

for value in root.iter('report_id'):
	report_id = value.text
	print "report generated will have id=", report_id

status = ""

def check_complete():
	#check task completed percentage
	global status
	proc5 = subprocess.Popen(['omp', '-u', user, '-w', password, '-G'], stdout=subprocess.PIPE)
	for line in proc5.stdout.readlines():
		tmp = line.split()
		if tmp[0] == task_id:
			if tmp[1] == "Running":
				print tmp[1], tmp[2]
			else:
				status = tmp[1]
				print tmp[1]
while True:
	check_complete()
	if status == "Done":
		break
	else:
		sleep(5)

print "Report id= ", report_id

#read report
proc4 = subprocess.Popen(['omp', '-u', user, '-w', password,'-iX', '<get_reports report_id="'+report_id+'" details="1"/>'], stdout=subprocess.PIPE)
for line in proc4.stdout.readlines():
	print >>f1, line.rstrip()

print "report written in 'report.xml' file"
