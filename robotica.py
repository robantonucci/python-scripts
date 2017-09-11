#!/usr/bin/env python

#######################################################################
#
# name:     robotica.py
# created:  4/21/2016
# updated:  
# author:   rob antonucci
# descript: This script will scan a site for robots.txt and then check
# to do:    if the links are accessable
#
########################################################################

import argparse
import requests
import sys

parser = argparse.ArgumentParser(
    description="Pretend your a robot")
parser.add_argument("target", help="Target website")
parser.add_argument("-u", "--user-agent", help="User Agent")
parser.add_argument("-n", "--not-found", help="Ignore 404", action="store_true")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)
args = parser.parse_args()
       
# set up variable names for the arguments
target = args.target
useragent = args.user_agent
robot = target
if not useragent:
    useragent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident/5.0)"
urls = []

# who doesnt like color??    
def colorize(string, style):
    # blue, green, yellow, purple, red, orange, bold, underline
    d = {'blue': '\033[94m', 'green': '\033[92m', 'yellow': '\033[93m',
         'bold': '\033[1m', 'underline': '\033[4m', 'purple':
         '\033[95m', 'red': '\033[91m', 'orange': '\33[38;5;202m'}
    if style in d:
        return d[style] + str(string) + '\033[0m'
    else:
        return string

def robot_scan(url):
    r = requests.get(url, headers={ "user-agent": useragent})
    return r.status_code,len(r.content)
    

if not target.endswith('/'):
    robot += '/'
robot += 'robots.txt'

r = requests.get(robot)
lines = r.text.split('\n')
for line in lines:
    if 'allow' in line.lower():
        line = line.split(':')[1].strip()
        if '#' in line:
            line = line.split('#')[0].strip()
        if not line.startswith('/'):
            url = '%s/%s' % (target, line)
        else:
            url = target + line
        status = robot_scan(url)
        out = '%s | %d | %s' % (status[0],status[1],url)
        if args.not_found:
            if status[0] == 200:
                print colorize(out, 'green')
        else:
            if status[0] == 200:
                print colorize(out, 'green')
            else:
                print colorize(out, 'red')
        


