#!/usr/bin/env python

########################################################################
#
# created:  2/18/2016
# updated:  4/08/2016
# author:   rob antonucci
# descript: This script will convert a given string into an NTLM hash
# to do:    interactive mode flag
#
########################################################################

import hashlib
import binascii
import argparse

parser = argparse.ArgumentParser(description="Create NTLM Hashes")
parser.add_argument('password', help="Input String")
args = parser.parse_args()

def hash_ntlm(password):
    password_hash = hashlib.new(
        'md4', password.strip().encode('utf-16le')).digest()
    return binascii.hexlify(password_hash)

print hash_ntlm(args.password)
