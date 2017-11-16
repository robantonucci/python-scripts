#!/usr/bin/env python
"""This script will encode/decode strings."""
import codecs
import base64
import argparse
import urllib
import hashlib
from sys import argv, exit
from binascii import hexlify

parser = argparse.ArgumentParser(
  description="This script will encode/decode strings")
parser.add_argument("input_string", help="Input String")

first_group = parser.add_mutually_exclusive_group()
first_group.add_argument(
  "-e", "--encode", help="Encode String", action="store_true")
first_group.add_argument(
  "-d", "--decode", help="Decode String", action="store_true")

second_group = parser.add_mutually_exclusive_group()
second_group.add_argument(
  "--base64", help="Base64", action="store_true")
second_group.add_argument(
  "--md5", help="MD5", action="store_true")
second_group.add_argument(
  "--ntlm", help="NTLM", action="store_true")
second_group.add_argument(
  "--rot13", help="ROT13", action="store_true")
second_group.add_argument(
   "--psh", help="PowerShell Base64 (Unicode)", action="store_true")
second_group.add_argument(
  "--url", help="URL", action="store_true")

if len(argv) < 4:
    parser.print_help()
    exit()
args = parser.parse_args()


class Str:

    def __init__(self, input_string, e):
        self.input_string = input_string
        self.e = e

    def base64(self):
        if self.e:
            return base64.b64encode(self.input_string)
        else:
            return base64.b64decode(self.input_string)

    def rot13(self):
        if self.e:
            return codecs.encode(self.input_string, 'rot13')
        else:
            return codecs.decode(self.input_string, 'rot13')

    def url(self):
        if self.e:
            return urllib.quote_plus(self.input_string)
        else:
            return urllib.unquote(self.input_string)

    def md5(self):
        if self.e:
            h = hashlib.md5()
            h.update(self.input_string)
            return h.hexdigest()
        else:
            return "https://hashkiller.co.uk/md5-decrypter.aspx"

    def ntlm(self):
        if self.e:
            h = self.input_string.encode('utf-16le')
            h = hashlib.new('md4', h).digest()
            return hexlify(h)
        else:
            return "https://hashkiller.co.uk/ntlm-decrypter.aspx"

    def psh(self):
        if self.e:
            return base64.b64encode(self.input_string.encode('utf-16le'))
        else:
            return base64.b64decode(self.input_string).decode('utf-16le')


if args.encode:
    str_object = Str(args.input_string, 1)
else:
    str_object = Str(args.input_string, 0)

if args.base64:
    print str_object.base64()
elif args.rot13:
    print str_object.rot13()
elif args.url:
    print str_object.url()
elif args.md5:
    print str_object.md5()
elif args.ntlm:
    print str_object.ntlm()
elif args.psh:
    print str_object.psh()
