#!/usr/bin/env python

import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def parse_args():
    ''' Create the arguments '''
    parser = argparse.ArgumentParser()
    parser.add_argument("-x", "--nmapxml", help="Nmap XML file to parse")
    return parser.parse_args()

def report_parser(report):
    ''' Parse the Nmap XML report '''
    for host in report.hosts:
        ip = host.address

        if host.is_up():
            hostname = 'N/A'
            # Get the first hostname (sometimes there can be multi)
            if len(host.hostnames) != 0:
                hostname = host.hostnames[0]

            print '\"{0}\",\"{1}\",\"{2}\",\"{3}\",\"{4}\",\"{5}\"'.format(ip, hostname,host.mac,host.vendor,host.os_class_probabilities(),host.services)

def main():
    args = parse_args()
    report = NmapParser.parse_fromfile(args.nmapxml)
    report_parser(report)

main()

