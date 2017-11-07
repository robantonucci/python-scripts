#!/usr/bin/env python
import codecs
import base64
from sys import argv
import argparse
import urllib
import hashlib

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
  "--rot13", help="ROT13", action="store_true")
second_group.add_argument(
  "--url", help="URL", action="store_true")

if len(argv) == 3:
    parser.print_help()
    exit(1)
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
            return "Need to crack MD5 :)"


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
else:
    print "Please specify a valid encoder/decoder!"
