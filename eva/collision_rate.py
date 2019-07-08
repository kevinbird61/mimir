#!/usr/bin/env python 

"""
Compute the collision rate of limited table size (for CAIDA)
Python version.
"""

import argparse, os 
import dpkt 

# CRC
from PyCRC.CRC32 import CRC32
from PyCRC.CRCCCITT import CRCCCITT

def IPv4_prettify(ipv4):
    return ':'.join('%d' % ord(b) for b in ipv4)

def process_pcap(args):
    # from args
    pcap_file = args.file
    table_size = args.size 
    ltt = args.ltt 
    raw = args.raw
    # read fuke
    f = open(pcap_file,'rb')
    pcap = dpkt.pcap.Reader(f)

    
    # global 
    timestamp = {}
    c_srcIP = ["null" for x in range(table_size)]
    c_dstIP = ["null" for x in range(table_size)]
    # pktcnt
    total = 0
    collision = 0
    total_pkt = 0
    nonIP_pkt = 0

    for ts, buf in pcap:
        # read from raw IP 
        # using try/catch block to avoid error corruption
        if raw is True:
            # ethernet mode
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
        else: 
            # raw ip mode
            try:
                ip = dpkt.ip.IP(buf)
            except:
                #print ("# NonIP packet.")
                continue
        
        # get flowid 
        flowid_str = IPv4_prettify(ip.src)+"|"+IPv4_prettify(ip.dst)
        flowid=( CRCCCITT().calculate(IPv4_prettify(ip.src)+IPv4_prettify(ip.dst)) )%table_size

        if flowid_str in timestamp:
            prev_ts = timestamp[flowid_str]
        else:
            prev_ts = 0
        
        # get timestamp 
        interval = ts-prev_ts 

        if interval > ltt:
            c_srcIP[flowid]="null"
            c_dstIP[flowid]="null"
        
        if c_srcIP[flowid] == "null" or c_dstIP[flowid] == "null":
            # just update
            c_srcIP[flowid] = IPv4_prettify(ip.src)
            c_dstIP[flowid] = IPv4_prettify(ip.dst)
        elif c_srcIP[flowid] != IPv4_prettify(ip.src) or c_dstIP[flowid] != IPv4_prettify(ip.dst):
        #if c_srcIP[flowid] != IPv4_prettify(ip.src) or c_dstIP[flowid] != IPv4_prettify(ip.dst):
            collision=collision+1
        else:
            total=total+1
        
        c_srcIP[flowid] = IPv4_prettify(ip.src)
        c_dstIP[flowid] = IPv4_prettify(ip.dst)

        # update lastseen 
        timestamp[flowid_str]=ts 

    f.close()
    

    # Print status
    print ("Source pcap filename:", pcap_file)
    print ("Raw mode: ", raw) 
    print ("Table size: ", table_size)
    print ("Long-term timeout: ", ltt)
    print ("Collision rate: ", float(collision)/float(total))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Reading pcap from RAW IP")
    # arguments
    parser.add_argument('--file', help="pcap filename", type=str, action="store", required=True)
    parser.add_argument('--size', help="table size", type=int, action="store", required=False, default=1024)
    parser.add_argument('--ltt', help="long-term timeout (sec)", type=int, action="store", required=False, default=50)
    parser.add_argument('--raw', help="raw IP pcap mode", action="store_true")

    args=parser.parse_args()

    # read & process the target pcap
    # check file
    if not os.path.exists(args.file):
        parser.print_help()
        parser.exit(1)
    # pass into function
    process_pcap(args)

