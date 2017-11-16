#!/usr/bin/env python
"""Scan a website for robots.txt then check each link."""
import argparse
import requests
from sys import argv, exit
from re import search

parser = argparse.ArgumentParser(
    description="This script will scan a site for robots.txt and then check"
                " if the links are accessable.")
parser.add_argument("target", help="Target website")
parser.add_argument("-u", "--user-agent", help="User Agent")
parser.add_argument("-n", "--not-found", help="Ignore 404",
                    action="store_true")

if len(argv) == 1:
    parser.print_help()
    exit()
args = parser.parse_args()

if not args.user_agent:
    useragent = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 7.1; Trident5.0"
    ")"


class Url:
    """Base class to fetch robots.txt file."""

    def __init__(self, url):
        """Initialize Url class."""
        self.url = url
        if not url.startswith('http://') or url.startswith('https://'):
            self.url = "http://" + url
        if url.endswith('/'):
            self.url = self.url[:-1]
        self.robot_txt = Scanner(self.url + '/robots.txt').text
        self.robot_entries = self.parse_robots()

    def parse_robots(self):
        """Parse the links from robots.txt."""
        entries = []
        for entry in self.robot_txt.split('\n'):
            match = search(r"[Aa][Ll]{2}[Oo][Ww]:\ (\/[^*$]{2,})", entry)
            if match:
                entries.append(match.group(1))
                if match.group(1).endswith('/'):
                    entries.append(match.group(1)[:-1])
        return list(set(entries))


class Scanner:
    """Scan URLs with requests."""

    def __init__(self, url):
        """Initialize Scanner class."""
        self.url = url
        self.scan(url)

    def scan(self, url):
        """Scan the URL."""
        r = requests.get(url, headers={"user-agent": useragent}, timeout=0.5)
        self.text = r.text
        self.status_code = r.status_code
        self.content_len = len(r.content)


try:
    url_obj = Url(args.target)
except Exception:
    print "[-] Didn't find a webserver on " + args.target
    exit(1)

for entry in url_obj.robot_entries:
    full_entry = url_obj.url + entry
    scan_obj = Scanner(full_entry)
    if scan_obj.status_code == 200:
        print scan_obj.content_len, full_entry
