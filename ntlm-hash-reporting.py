#!/usr/bin/env python

########################################################################
#
# name:     ntlm-hash-reporting.py
# created:  2/22/2016
# updated:  3/30/2016
# author:   rob antonucci
# descript: This script will look through a NTLM hash dump and check
#           for certain passwords
# to do:    
#
########################################################################

import hashlib
import binascii
import re
import argparse
import sys

parser = argparse.ArgumentParser(
    description="Report on NTLM Hashe Dumps")
parser.add_argument("-f", "--file",
    help="Import passwords from file")
parser.add_argument("-n", "--hashes",
    help="Import hashes from file")
parser.add_argument("-p", "--password",
    help="Password to use")
parser.add_argument("-u", "--username",
    help="Check username as password", action="store_true")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()
   
# set up variable names for the arguments
passfile = args.file
hashfile = args.hashes
password = args.password
useraspass = args.username

counter = 0
d = {}

def hash_ntlm(password):
    try:
      hash = hashlib.new('md4', password.encode('utf-16le')).digest()
      return binascii.hexlify(hash)
    except:
      print "[-] Failed on %s" % password
    
if password:
    hashed_password = hash_ntlm(password.strip())
    d[password] = hashed_password
elif passfile:
    with open(passfile) as infile:
        for password in infile:         
            hashed_password = hash_ntlm(password.strip())
            d[password] = hashed_password
    infile.close()

with open(hashfile) as infile:
    for line in infile:
        if useraspass:
            match = re.search('(.+):\d+:.+:(.+):::', line)
            if match:
                user = match.group(1)
                ntlm = match.group(2)
                user_as_ntlm = hash_ntlm(user)
                upper_as_ntlm = hash_ntlm(user.upper())
                lower_as_ntlm = hash_ntlm(user.lower())
                if user_as_ntlm == ntlm:
                    print "%s: %s" % (user, user)
                    counter += 1
                elif upper_as_ntlm == ntlm:
                    print "%s: %s" % (user.upper(), user)
                    counter += 1
                elif lower_as_ntlm == ntlm:
                    print "%s: %s" % (user.lower(), user)
                    counter += 1
        else:
            for password, hashed_password in d.iteritems():
                match = re.search("(.+):\d+:.+:(%s):::"
                                   % hashed_password, line)
                if match:
                    print "%s: %s" % (password, match.group(1))                     
                    counter += 1

print "%s account(s) found." % counter
