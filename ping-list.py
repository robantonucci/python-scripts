#!/usr/bin/env python

########################################################################
#
# name:     ping-list.py
# created:  4/14/2016
# updated:  5/26/2016
# author:   rob antonucci
# descript: This script will ping a list of IPs
# to do:    
#
########################################################################

import subprocess
import argparse
import csv
import re
import sys
import pyping

parser = argparse.ArgumentParser(
    description="Check if list of IPs responds to ping")
parser.add_argument("input", help="Plaintext list of IPs")
parser.add_argument("-o", "--output", help="Output to CSV file")
parser.add_argument("--dead", help="Only show dead systems",
    action="store_true")
parser.add_argument("--alive", help="Only show alive systems",
    action="store_true")    

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

# set up variable names
ifile = args.input
ofile = args.output
dead = args.dead
alive = args.alive
in_file = open(ifile, 'r')
result = []

if alive and dead:
    print "[-] Please choose alive or dead.."
    exit(1)

if ofile:
    out_file = open(ofile, 'wb')
    writer = csv.writer(out_file, delimiter = '\n')

for line in in_file:
    server = line.strip()
    if line != '':
        try:
            r = pyping.ping(server, count=1)
            if r.ret_code == 0:
                out = '%s,Alive' % server
            else:
                out = '%s,Dead' % server
        except:
            out = '%s,Dead' % server
        if dead:
            if 'Dead' in out:
                print out
        elif alive:
            if 'Alive' in out:
                print out
        else:
            print out
        result.append(out)

in_file.close()

if ofile:
    writer.writerow(result)
    out_file.close()
