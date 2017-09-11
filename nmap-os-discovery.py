#!/usr/bin/env python

########################################################################
#
# name:     nmap-os-discovery.py
# created:  4/13/2016
# updated:  5/13/2016
# author:   rob antonucci
# descript: This script will use nmap to grab OS details via SMB script
# to do:    html reporting, sort by ip, csv, psloggedon
#
########################################################################

import os
import subprocess
import sys
import argparse
import csv
import re
import collections
import time
import netaddr
import getpass

parser = argparse.ArgumentParser(
    description="This script is a wrapper for Nmap to find OS Levels via SMB")
parser.add_argument("-u", "--user",
    help="SMB user")
parser.add_argument("-d", "--domain",
    help="SMB user domain")
parser.add_argument("-p", "--password",
    help="SMB password")
parser.add_argument("--hash",
    help="SMB NTLM Hash")    
parser.add_argument("-i", "--input",
    help="Load subnets or IPs from file")
parser.add_argument("-o", "--output",
    help="Output to a CSV file")
parser.add_argument("--os-filter",
    help="Show only specific OS's")
parser.add_argument("-s", "--subnet",
    help="Scan single subnet")
parser.add_argument("-f", "--full",
    help="Full SMB scan with UDP", action="store_true")  

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

# set up variable names for the arguments
user = args.user
domain = args.domain
password = args.password
subnet = args.subnet
in_file = args.input
out_file = args.output
os_filter = args.os_filter
udp_scan = args.full
hash = args.hash
os_collection = {}

# check if arguments make sense
if subnet and in_file:
    print "[-] Pick a single subnet or input file"
    sys.exit(1)
if user and not domain:
    print "[-] Please specify domain"
    sys.exit(1)
if password and hash:
    print "[-] Please specify password or hash"
    sys.exit(1)
if hash:
    if len(hash) != 32:
        print "[-] NTLM hash is wrong length"
        sys.exit(1)
if user and not password:
    print "[*] Careful typing, you may lock your account out!!"
    password = getpass.getpass(stream=sys.stderr)
    
# check if nmap is installed
try:
    devnull = open(os.devnull)
    subprocess.Popen(['nmap'], stdout=devnull, stderr=devnull).communicate()
except OSError as e:
    if e.errno == os.errno.ENOENT:
        print ("[-] Nmap is not installed, try this..\napt-get update &&"
               " apt-get install nmap -y")
        sys.exit(1)

# who doesnt like color??    
def colorize(string, style):
    # blue, green, yellow, purple, red, orange, bold, underline
    d = {'blue': '\033[94m', 'green': '\033[92m', 'yellow': '\033[93m',
         'bold': '\033[1m', 'underline': '\033[4m', 'purple':
         '\033[95m', 'red': '\033[91m', 'orange': '\33[38;5;202m'}
    if style in d:
        return d[style] + str(string) + '\033[0m'
    else:
        return string

def nmapScan(subnet):
    nmap = ("nmap -Pn -n --open --stats-every 120 --script "
            "smb-os-discovery -p ")
    if udp_scan:
        nmap += "U:137,T:139,T:445 -sU -sS "
    else:
        nmap += "445 "
    if user:
        nmap += ("--script-args smbusername=%s,smbdomain=%s,"
            % (user, domain))        
        if password:
            nmap += "smbpassword=%s " % password
        elif hash:
            nmap += "smbhash=%s " % hash
    if in_file:
        nmap += "-iL %s" % in_file
    elif subnet:
        nmap += subnet
    #out = subprocess.check_output(nmap, shell=True)
    # this will stream stdout for timing info
    proc = subprocess.Popen(nmap,
                       shell=True,
                       stdout=subprocess.PIPE,
                       )
    while proc.poll() is None:
        out = proc.stdout.readline()
        out = out.strip()
        if out:
            out = out.split('\n')
            for line in out:
                stats_match = re.search("Stats:", line)
                ip_match = re.search("Nmap scan report for (?:.+ \\()?("
                                     "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\."
                                     "\\d{1,3})", line)
                os_match = re.search("OS: (.+)", line)
                computer_match = re.search("Computer name: (.+)", line)
                fqdn_match = re.search("FQDN: (.+)", line)
                workgroup_match = re.search("Workgroup: (.+)", line)
                #print line
                if stats_match:
                    print line
                if ip_match:
                    ip = ip_match.group(1)
                    os_collection[ip] = {}
                    os_collection[ip]['OS'] = ''
                    os_collection[ip]['NAME'] = ''
                    os_collection[ip]['FQDN'] = ''
                    os_collection[ip]['WORKGROUP'] = ''
                if os_match:
                    os = os_match.group(1)
                    os_collection[ip]['OS'] = os
                if computer_match:
                    computer = computer_match.group(1)
                    os_collection[ip]['NAME'] = computer
                if fqdn_match:
                    fqdn = fqdn_match.group(1)
                    os_collection[ip]['FQDN'] = fqdn
                if workgroup_match:
                    workgroup = workgroup_match.group(1)
                    os_collection[ip]['WORKGROUP'] = workgroup

# run the main function
# first lets see how many hosts were scanning
# this doenst work very well..
subnet_counter = 0
if subnet:
    re_ip = re.search('\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
                          subnet)
    if re_ip:
        # this will calculate the number of hosts based on CIDR
        if '-' in subnet or ',' in subnet:
            ip_list = []
            if '/' in subnet:
                subnet = subnet.replace('0/24', '0-255')
            ips = netaddr.iter_nmap_range(subnet)
            for ip in ips:
                ip_list.append(ip)
            subnet_counter = len(ip_list)
        else:
            subnet_counter = netaddr.IPNetwork(subnet).size
    else:
        subnet_counter = 1

elif in_file:
    f = open(in_file, 'r')
    for line in f:
        re_ip = re.search('\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}',
                          line)
        if re_ip:
            subnet_counter += netaddr.IPNetwork(line.strip()).size
        else:
            subnet_counter += 1

start_time = time.time()
print ("Scan started : %s hosts at %s\n" % (subnet_counter,
   colorize(time.strftime('%Y-%m-%d %l:%M:%S%p'), 'bold')))

nmapScan(subnet)

# clean up dictionary by removing empty OS results
for ip in os_collection.keys():
    if os_collection[ip]['OS'] == '':
        del os_collection[ip]

# order the dictionary by IP
for ip in os_collection.keys():
    sort = ip.split('.')
    first = sort[0]
    second = sort[1]
    third = sort[2]
    fourth = sort[3]
    # pad the octets with zeros until they reach 3 integers
    while len(first) < 3:
        first = '0' + first
    while len(second) < 3:
        second = '0' + second
    while len(third) < 3:
        third = '0' + third
    while len(fourth) < 3:
        fourth = '0' + fourth
    sorted_ip = "%s.%s.%s.%s" % (first,second,third,fourth)
    os_collection[ip]['SORT'] = sorted_ip

os_collection_sorted = sorted(os_collection, key=lambda x:
    (os_collection[x]['SORT']))

for ip in os_collection_sorted:
    workgroup = os_collection[ip]['WORKGROUP']
    fqdn = os_collection[ip]['FQDN']
    os = os_collection[ip]['OS']
    name = os_collection[ip]['NAME']
    print_out = (
        "IP           : %s\n"
        "OS           : %s\n"
        "NAME         : %s\n"
        "FQDN         : %s\n"
        "WORKGROUP    : %s\n" % (ip, os, name, fqdn, workgroup))
    if os_filter:
        if os_filter.upper() in os_collection[ip]['OS'].upper():
            print print_out
    else:
        print print_out

# lets count our results
print "Hosts Found  : %s" % len(os_collection)
'''
xp_counter = 0
for ip in os_collection_sorted:
    if 'XP' in os_collection[ip]['OS'].upper():
        xp_counter += 1
print "XP Hosts     : %s" % colorize(xp_counter, 'bold')
'''
end_time = time.time()
hours, rem = divmod(end_time - start_time, 3600)
minutes, seconds = divmod(rem,60)
print ("Time Elapsed : {:0>2}:{:0>2}:{:05.2f}".format(int(hours),
    int(minutes),seconds))
print ("Scan Finished: %s" %
    colorize(time.strftime('%Y-%m-%d %l:%M:%S%p'), 'bold'))

if out_file:
    with open(out_file, 'w') as csvout:
        fieldnames = ['IP', 'OS', 'NAME', 'FQDN', 'WORKGROUP']
        writer = csv.DictWriter(csvout, fieldnames=fieldnames)
        writer.writeheader()
        for ip, val in os_collection.items():               
            os = os_collection[ip]['OS']
            name = os_collection[ip]['NAME']
            fqdn = os_collection[ip]['FQDN']
            workgroup = os_collection[ip]['WORKGROUP']
            writer.writerow({
                'IP': ip, 'OS': os , 'NAME': name, 'FQDN': fqdn,
                'WORKGROUP': workgroup})
