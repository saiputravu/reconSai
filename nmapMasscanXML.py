#!/usr/bin/python3
#
# import masscan output and run an nmap scan on the results
#

import sys
import argparse
import os
import json

from multiprocessing.pool import ThreadPool
from collections import defaultdict

parser = argparse.ArgumentParser(description='Import masscan results and run an nmap scan against the target.')
parser.add_argument('scanfile', type=str, help='JSON file containing masscan results.')
parser.add_argument('outdir', type=str, help='directory to ouput')
parser.add_argument('--threads', type=int, default=5, help='Number of threads to run nmaps')
args = parser.parse_args()

def do_os_scan(target, options, directory):
    os.system("sudo nmap %s %s -oN %s" % (str(target), options, directory+"/nmap-"+str(target)))

def do_nmap(target, ports, directory):
    # space on the end is on purpose
    options = "-sC -sV -O -p '{}' ".format(', '.join(map(str, ports)))
    print("Getting ready to scan {0} on ports {1}".format(target, ', '.join(map(str, ports))))

    try:
        do_os_scan(target, options, directory)
    except:
        print("Error with ip: {}".format(target))

def parse_fromfile(json_scan_file):
    '''
        Returns a dictionary in format
        {
            "127.0.0.1": [80, 443, 22 ... ],
            ...
        }
    '''
    with open(json_scan_file, 'r') as f:
        data = json.loads(f.read())

    hosts = {k:[] for k in set([i['ip'] for i in data])}
    for d in data:
        hosts[d['ip']].append(d['port'])

    return hosts


def main(scan_file, directory, threads):
    try:
        report = parse_fromfile(scan_file)
    except Exception as e:
        print("Scan parsing failed: {0}".format(e))
        return
    
    # Multithreading
    threads = 5 
    pool = ThreadPool(threads)
    for ip, ports in report.items():
        pool.apply_async(do_nmap, (ip, ports, directory))

    pool.close()
    pool.join()
    print("Nmap Scanning complete, check report files")


if __name__ == '__main__':
    main(args.scanfile, args.outdir, args.threads)
