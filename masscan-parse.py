#!/usr/bin/env python
"""This script will parse the output of masscan."""
import argparse
from sys import argv
from re import search

parser = argparse.ArgumentParser(
    description="For parsing the results of masscan.")
parser.add_argument("input_file", help="masscan file to parse")

if len(argv) < 2:
    parser.print_help()
    exit(1)
args = parser.parse_args()


class Host:
    """Host class."""

    def __init__(self, host, port, proto):
        """Initialize Host object."""
        self.ports = []
        self.host = host
        self.add_port(port, proto)

    def add_port(self, port, proto):
        if proto == 'tcp':
            port = 'T:' + port
        elif proto == 'udp':
            port = 'U:' + port
        self.ports.append(port)

    def format_print(self, type):
        """Type can be 'tcp', 'udp' or 'tcp/udp'."""
        ports = []
        for port in self.ports:
            ports.append(port[2:])
        ports = ','.join(ports)
        if type == 'tcp':
            print "nmap -A -T5 -v -p %s %s" % (ports, self.host)
        elif type == 'udp':
            print "nmap -A -T5 -v -sU -p %s %s" % (ports, self.host)
        elif type == 'tcp/udp':
            ports = ','.join(self.ports)
            print "nmap -A -T5 -v -sSU -p %s %s" % (ports, self.host)


f = open(args.input_file, 'r')
f_lines = f.readlines()
hosts = {}
for line in f_lines:
    match = search(r"open port (\d+)/(tcp|udp) on (\d+\.\d+\.\d+\.\d+)", line)
    if match:
        port = match.group(1)
        proto = match.group(2)
        host = match.group(3)
        if host in hosts.keys():
            hosts[host].add_port(port, proto)
        else:
            hosts[host] = Host(host, port, proto)

for host in hosts.values():
    tcp = False
    udp = False
    for port in host.ports:
        if port.startswith('T:'):
            tcp = True
        elif port.startswith('U:'):
            udp = True
    if tcp and udp:
        host.format_print('tcp/udp')
    elif tcp:
        host.format_print('tcp')
    elif udp:
        host.format_print('udp')
