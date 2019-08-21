#!/usr/bin/env python3

""" Nmap automated scan for a list of hosts"""
""" Make my life easier when taking the OSCP """

import os
import sys
import subprocess
from optparse import OptionParser

scan_dir = '/root/OSCP/scans/'
#scan_dir = '/tmp/OSCP/scans/'
oscp_ips = '/root/OSCP/OSCP-IPS.txt'

def create_dirs(ips, scan_dir):
    """ Create directory structure """
    with open(ips) as f:
        for ip in f.readlines():
            our_scan_dir = scan_dir + ip.strip()
            if not os.path.exists(our_scan_dir):
                os.makedirs(our_scan_dir)
                print("Directory:", our_scan_dir , "Created")
            else:
                print("Directory:", our_scan_dir, "already exists")


def tcp_scan(hosts):
    """ Perform nmap TCP scan """
    with open(hosts) as f:
        for ip in f.readlines():
            out_dir = scan_dir + ip.strip() + '/' + ip.strip() + "-tcp"
            subprocess.run(["nmap", "-T4", "-sV", "-A", "-oA" , out_dir,
                ip.strip()])


def udp_scan(hosts):
    """ Perform nmap UDP scan """
    with open(hosts) as f:
        for ip in f.readlines():
            out_file = scan_dir + ip.strip() + '/' + ip.strip() + "-udp"
            subprocess.run(["nmap", "-T4", "-sU","-oA" , out_file,
                ip.strip()])


if __name__ == '__main__':
    create_dirs(oscp_ips, scan_dir)
    tcp_scan(oscp_ips)
    udp_scan(oscp_ips)