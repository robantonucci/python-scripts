#!/usr/bin/env python

########################################################################
#
# name:     decoder.py
# created:  4/13/2016
# updated:  5/13/2016
# author:   rob antonucci
# descript: For easy python decoding/encoding
# to do:    
#
########################################################################

import codecs
import base64
import sys
import argparse
import urllib
import hashlib

parser = argparse.ArgumentParser(
    description="This script will encode/decode strings")
parser.add_argument("string", help="Target String")

first_group = parser.add_mutually_exclusive_group()
first_group.add_argument("-e", "--encode",
    help="Encode String", action="store_true")
first_group.add_argument("-d", "--decode",
    help="Decode String", action="store_true")  

second_group = parser.add_mutually_exclusive_group()      
second_group.add_argument("--base64",
    help="Base64", action="store_true")
second_group.add_argument("--md5",
    help="MD5", action="store_true")    
second_group.add_argument("--rot13",
    help="ROT13", action="store_true")
second_group.add_argument("--url",
    help="URL", action="store_true")    

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()

if args.base64:
    if args.encode:
        print base64.b64encode(args.string)
    elif args.decode:
        print base64.b64decode(args.string)
elif args.rot13:
    if args.encode:
        print codecs.encode(args.string,'rot13')
    elif args.decode:
        print codecs.decode(args.string,'rot13')        
elif args.url:
    if args.encode:
        print urllib.quote_plus(args.string)
    elif args.decode:
        print urllib.unquote(args.string)
elif args.md5:
    if args.encode:
        m = hashlib.md5()
        m.update(args.string)
        print m.hexdigest()
    elif args.decode:
        print "Need to crack MD5 :)"


