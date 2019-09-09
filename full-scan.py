#!/usr/bin/env python3
#
# TODO:
# - validate IP addresses
# - validate directory and location
# - [DONE] fix argparse
# - add command line argument for ctfrecon

""" Nmap automated scan for a list of hosts"""
""" Make my life easier when taking the OSCP """

import argparse
import os
import sys
import socket
import subprocess
import ctfrecon
from optparse import OptionParser

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


def tcp_scan(hosts, scan_dir):
    """ Perform nmap TCP scan """
    with open(hosts) as f:
        for ip in f.readlines():
            out_dir = scan_dir + ip.strip() + '/' + ip.strip() + "-tcp"
            subprocess.run(["nmap", "-T4", "-sV", "-A", "-oA" , out_dir,
                ip.strip()])


def udp_scan(hosts, scan_dir):
    """ Perform nmap UDP scan """
    with open(hosts) as f:
        for ip in f.readlines():
            out_file = scan_dir + ip.strip() + '/' + ip.strip() + "-udp"
            subprocess.run(["nmap", "-T4", "-sU","-oA" , out_file,
                ip.strip()])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Nmap wrapper for inital enumeration scanning')
    parser.add_argument('--scan_dir', help='Directory to store scan results',
            action="store", dest="scan_dir", type=str,
            required=True)
    parser.add_argument('--ip_list', help='List of IP Addresses to scan',
            action="store", dest="ips", type=str, required=True)
    results = parser.parse_args()

    create_dirs(results.ips, results.scan_dir)
    tcp_scan(results.ips, results.scan_dir)
    udp_scan(results.ips, results.scan_dir)
 
    """parse, search, and create ctfrecon results in host directories"""
    parsedPathList = []
    with open(results.ips) as f:
        for hostIP in f.readlines():
            parsedPathList.append(results.scan_dir + hostIP.strip() + '/' + hostIP.strip() + "-tcp.xml")
    f.close()

    parsedHosts = ctfrecon.parse_nmap(parsedPathList)
    searchDict = ctfrecon.create_nmap_search_list(parsedHosts)
    results = ctfrecon.search_exploits(searchDict, ctfrecon.open_CSV(ctfrecon.SSPATH + 'files_exploits.csv'))
    indexResults = ctfrecon.search_exploits_index(searchDict, ctfrecon.open_CSV(ctfrecon.SSPATH + 'files_exploits.csv'))
    finalResults = ctfrecon.remove_duplicates(results, indexResults)
    for path in parsedPathList:
        ctfrecon.create_results_files(path, finalResults, parsedHosts, searchDict)


