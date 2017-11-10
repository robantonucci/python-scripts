#!/usr/bin/env python
import argparse
import pyping
from sys import argv, exit


parser = argparse.ArgumentParser(
  description="Check if list of IPs responds to ping")
parser.add_argument("input", help="Plaintext list of IPs")
parser.add_argument("-o", "--output", help="Output to CSV file")
parser.add_argument("--dead", help="Only show dead systems",
                    action="store_true")
parser.add_argument("--alive", help="Only show alive systems",
                    action="store_true")

if len(argv) < 2:
    parser.print_help()
    exit()
args = parser.parse_args()
if args.alive and args.dead:
    print "[-] Please choose alive or dead."
    exit()


class Computer:

    total_computers = 0

    def __init__(self, name):
        self.name = name.strip()
        self.status = 'Dead'
        Computer.total_computers += 1

    def ping(self):
        p = pyping.ping(self.name, count=1)
        if p.ret_code == 0:
            self.status = 'Alive'

    def format(self):
        return "%s,%s" % (self.name, self.status)


in_file = open(args.input, 'r')
computers = [Computer(name=name) for name in in_file]
in_file.close()
if args.output:
    out_file = open(args.output, 'wb')

for comp_obj in computers:
    if comp_obj.name != '':
        try:
            comp_obj.ping()
        except Exception as e:
            print "[-] EXCEPTION on %s: %s" % (comp_obj.name, str(e))
        if args.dead or args.alive:
            if args.dead and comp_obj.status == 'Dead':
                print comp_obj.format()
            elif args.alive and comp_obj.status == 'Alive':
                print comp_obj.format()
        else:
            print comp_obj.format()
        if args.output:
            out_file.write(comp_obj.format() + '\n')

print "Pinged %d computer(s)." % Computer.total_computers
if args.output:
    out_file.close()
