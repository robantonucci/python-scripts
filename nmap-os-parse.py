"""This script will parse the results of Nmap's smb-os-discovery.nse."""
import argparse
import csv
from re import search
from sys import argv, exit

parser = argparse.ArgumentParser(
    description="For parsing the results of Nmap's smb-os-discovery.nse\n"
    "\nnmap -sU -sS --script smb-os-discovery.nse --open -Pn -oN os-scan -n "
    "--script-args=smbuser=svc_account,smbpass=password,smbdomain=contoso.com "
    "-p U:137,T:139,T:445 10.0.0.0/8",
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
        self.os = ''
        self.fqdn = ''
        self.workgroup = ''
        self.name = ''

    def format_print(self):
        """Print out fields."""
        return "%s,%s,%s,%s,%s" % (self.ip, self.name, self.fqdn, self.os,
                                   self.workgroup)

    def format_csv(self):
        """Fornat CSV out dict."""
        return {'IP': self.ip, 'OS': self.os, 'NAME': self.name, 'FQDN':
                self.fqdn, 'WORKGROUP': self.workgroup}


nmap_input = open(args.input_file, 'r')
csv_output = open(args.output_file, 'wb')
field_names = ['IP', 'NAME', 'FQDN', 'OS', 'WORKGROUP']
writer = csv.DictWriter(csv_output, fieldnames=field_names)
writer.writeheader()

for line in nmap_input:
    ip_match = search("Nmap scan report for (?:.+ \\()?(\\d{1,3}\\.\\d{1,3}"
                      "\\.\\d{1,3}\\.\\d{1,3})", line)
    fqdn_match = search("FQDN: (.+)", line)
    workgroup_match = search("Workgroup: (.+)", line)
    os_match = search("OS: (.+)", line)
    name_match = search("Computer name: (.+)", line)
    if ip_match:
        ip = ip_match.group(1)
        host_obj = Host(ip)
    elif os_match:
        os = os_match.group(1)
        host_obj.os = os
    elif fqdn_match:
        fqdn = fqdn_match.group(1)
        host_obj.fqdn = fqdn
    elif workgroup_match:
        workgroup = workgroup_match.group(1)
        host_obj.workgroup = workgroup
    elif name_match:
        name = name_match.group(1)
        host_obj.name = name
    elif "System time:" in line:
        if host_obj.os != '':
            print host_obj.format_print()
            writer.writerow(host_obj.format_csv())
nmap_input.close()
csv_output.close()
