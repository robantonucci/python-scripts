#!/usr/bin/env python
"""This script will parse the results of Nmap's ssh-hostkey.nse."""
import argparse
import csv
from re import search
from sys import argv, exit

parser = argparse.ArgumentParser(
    description="For parsing the results of Nmap's ssh-hostkey.nse\n"
    "\nnmap -p22 --script ssh-hostkey -sV -Pn -oN ynhh/ssh-scan.nmap "
    "--open 10.0.0.0/8",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("input_file", help="Nmap file to parse")
parser.add_argument("output_file", help="CSV output file")

if len(argv) < 3:
    parser.print_help()
    exit(1)
args = parser.parse_args()


class Host:
    """Host object parsed from input file."""

    def __init__(self, ip):
        """Initialize Host object."""
        self.ip = ip
        self.dns = ''
        self.ssh = ''
        self.fingerprint = ''

    def format_print(self):
        """Print out fields."""
        return "%s,%s,%s,%s" % (self.ip, self.dns, self.ssh, self.fingerprint)

    def format_csv(self):
        """Fornat CSV out dict."""
        return {'IP': self.ip, 'DNS': self.dns, 'VERSION': self.ssh,
                'FINGERPRINT': self.fingerprint}


nmap_input = open(args.input_file, 'r')
nmap_lines = nmap_input.readlines()
csv_output = open(args.output_file, 'wb')
field_names = ['IP', 'DNS', 'VERSION', 'FINGERPRINT']
writer = csv.DictWriter(csv_output, fieldnames=field_names)
writer.writeheader()
host_obj = ''

# for line in nmap_input:
for i in range(0, len(nmap_lines)):
    line = nmap_lines[i]
    ip_match = search(r"Nmap scan report for ((?:\d{1,3}.){3}\d{1,3})", line)
    dns_match = search(r"Nmap scan report for ([^\ ]+) \(((?:\d{1,3}.){3}"
                       "\d{1,3})\)", line)
    version_match = search(r"open\ + ssh\ +(.+)", line)
    try:
        if ip_match:
            ip = ip_match.group(1)
            host_obj = Host(ip)
        elif dns_match:
            ip = dns_match.group(2)
            dns = dns_match.group(1)
            host_obj = Host(ip)
            host_obj.dns = dns
        elif "fingerprint-strings:" in line:
            parse = nmap_lines[i+2].split('|', 1)[1]
            fingerprint_match = search(r"^\|_| +(SSH-.+)", parse)
            host_obj.fingerprint = fingerprint_match.group(1)
        elif version_match:
            ssh = version_match.group(1)
            host_obj.ssh = ssh
        elif "Nmap scan report for" in nmap_lines[i+1] and host_obj != '':
            print host_obj.format_print()
            writer.writerow(host_obj.format_csv())
        elif "Post-scan script" in line:
            print host_obj.format_print()
            writer.writerow(host_obj.format_csv())
    except IndexError:
        '''Last line + 1 will cause an exception.'''
        pass

nmap_input.close()
csv_output.close()
