#!/usr/bin/env python
"""This script will analyze a NTLM hashdump for specified passwords."""
import hashlib
from binascii import hexlify
import re
import argparse
from sys import argv, exit
from passlib.hash import lmhash

parser = argparse.ArgumentParser(
  description="Report on NTLM Hash Dumps\n"
  "Expected hash format: Administrator:500:000:000:::")
parser.add_argument("-f", "--file", help="Import passwords from file")
parser.add_argument("-n", "--hashes", help="Import hashes from file")
parser.add_argument("-p", "--password", help="Password to use")
parser.add_argument("-u", "--username", help="Check username as password",
                    action="store_true")

if len(argv) < 4:
    parser.print_help()
    exit()

args = parser.parse_args()


class Password:
    """Password class."""

    def __init__(self, password):
        """Initialize password object."""
        self.password = password.strip()
        self.ntlm = self.hash(self.password)
        self.lm = self.lm_hash(self.password)

    def hash(self, password):
        """Hash the given password as NTLM."""
        h = password.encode('utf-16le')
        h = hashlib.new('md4', h).digest()
        return hexlify(h)

    def lm_hash(self, password):
        """Hash the given password as LM."""
        h = lmhash.hash(password.strip())
        return h


class ParseHashLine:
    """Parse the username and NTLM hash from input string."""

    def __init__(self, unparsed_str):
        """Initialize class."""
        self.unparsed_str = unparsed_str.strip()
        self.user = ''
        self.ntlm_hash = ''
        self.lm_hash = ''
        self.parse(self.unparsed_str)

    def parse(self, unparsed_str):
        """Parse the string and return a user and ntlm hash."""
        match = re.search('(.+):\d+:(.+):(.+):::', unparsed_str)
        if match:
            self.user = match.group(1)
            self.lm_hash = match.group(2)
            self.ntlm_hash = match.group(3)
        else:
            return False


if args.file:
    """If there is a list of passwords, create an object for each."""
    in_file = open(args.file, 'r')
    passwords = [Password(password=password) for password in in_file]
    in_file.close()
elif args.password:
    """Just use one given password."""
    passwords = [Password(args.password)]

with open(args.hashes) as in_hashes:
    ntlm_counter = 0
    lm_counter = 0
    for line in in_hashes:
        """Prevent LM hashes from being displayed more than once."""
        found_lm = False
        hash_str = ParseHashLine(line)
        if args.username:
            """Try the username as given, upper and lower."""
            try:
                unique_pass = list(set([hash_str.user, hash_str.user.upper(),
                                   hash_str.user.lower()]))
                passwords = [Password(password=password) for password in
                             unique_pass]
            except Exception:
                pass

        for password_obj in passwords:
            if password_obj.ntlm == hash_str.ntlm_hash:
                print "NTLM: %s : %s" % (hash_str.user, password_obj.password)
                ntlm_counter += 1
            elif password_obj.lm == hash_str.lm_hash and not found_lm:
                print "LM  : %s : %s" % (hash_str.user,
                                         password_obj.password.upper())
                found_lm = True
                lm_counter += 1
print "\n[+] Found %d NTLM passwords, %d LM passwords" % (ntlm_counter,
                                                          lm_counter)
