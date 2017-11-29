#!/usr/bin/env python
"""This script will parse the output of Invoke-Mimikatz."""
import argparse
from sys import argv, exit

parser = argparse.ArgumentParser(
    description="For parsing the results of Invoke-Mimikatz.")
parser.add_argument("input_file", help="Nmap file to parse")

if len(argv) < 2:
    parser.print_help()
    exit(1)
args = parser.parse_args()


class Password:
    """Password class from msv, tspkg, wdigest, kerberos, ssp or credman."""

    def __init__(self, raw):
        """Initialize Password object."""
        self.raw = raw
        self.username = raw[3]
        self.domain = raw[7]
        self.password = ''
        self.ntlm = ''
        self.lm = '0' * 32
        self.sha1 = ''
        if self.username.endswith('$'):
            computer_account = True
        else:
            computer_account = False
        if raw[9] == 'LM' and not computer_account:
            """Line should contain LM an NTLM hashes."""
            if len(raw[11]) == 32 and len(raw[15]) == 32:
                self.lm = raw[11]
                self.ntlm = raw[15]
        elif raw[9] == 'NTLM' and not computer_account:
            """Line should contain NTLM and SHA1 hashes."""
            if len(raw[11]) == 32 and len(raw[15]) == 40:
                self.ntlm = raw[11]
                self.sha1 = raw[15]
        elif raw[9] == 'Password' and not computer_account:
            if raw[11] != '(null)':
                self.password = raw[11]

    def format_print(self):
        """Print out fields."""
        if self.password != '':
            line = "%s:%s:%s" % (self.username, self.domain, self.password)
            return (1, line)
        elif self.ntlm != '':
            line = "%s:%s:%s:%s" % (self.username, self.domain, self.lm,
                                    self.ntlm)
            return (2, line)
        else:
            return False


class Sam:
    """Sam class from local SAM db."""

    def __init__(self, raw):
        """Initialize Sam object."""
        self.raw = raw
        self.username = raw[6]
        self.rid = raw[3][1:-1]
        self.lm = '0' * 32
        self.ntlm = '0' * 32
        if len(raw) > 12:
            self.lm = raw[9]
            self.ntlm = raw[12]
        elif len(raw) == 12:
            self.ntlm = raw[11]

    def format_print(self):
        """Print out fields."""
        line = "%s:%s:%s:%s:::" % (self.username, self.rid, self.lm, self.ntlm)
        return line


mimi_in = open(args.input_file, 'r')
mimi_lines = mimi_in.readlines()
passwords = []
hashes = []
sam = []

for i in range(0, len(mimi_lines)):
    if "Username" in mimi_lines[i]:
        mimi_lines[i].strip()
        parse = "%s %s %s %s" % (mimi_lines[i], mimi_lines[i+1],
                                 mimi_lines[i+2], mimi_lines[i+3])
        password_obj = Password(parse.split())
        output = password_obj.format_print()
        if output:
            if output[0] == 1:
                passwords.append(output[1])
            elif output[0] == 2:
                hashes.append(output[1])
    elif "RID" in mimi_lines[i]:
        parse = "%s %s %s %s" % (mimi_lines[i], mimi_lines[i+1],
                                 mimi_lines[i+2], mimi_lines[i+3])
        sam_obj = Sam(parse.split())
        output = sam_obj.format_print()
        if output:
            sam.append(sam_obj.format_print())

mimi_in.close()

for password in list(sorted(set(passwords))):
    print password
print
for hash in list(sorted(set(hashes))):
    print hash
print
for account in sam:
    print account
