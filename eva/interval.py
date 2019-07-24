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
    #table_size = args.size 
    # ltt = args.ltt 
    raw = args.raw
    # read fuke
    f = open(pcap_file,'rb')
    pcap = dpkt.pcap.Reader(f)

    
    # global 
    timestamp = {}
    interval_dist = {}
    total_pkt = 0
    nonIP_pkt = 0

    for ts, buf in pcap:
        # read from raw IP 
        # using try/catch block to avoid error corruption
        if raw is True:
            # raw ip mode
            try:
                ip = dpkt.ip.IP(buf)
            except:
                #print ("# NonIP packet.")
                continue
        else: 
            # ethernet mode
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                continue
            # check if IP existed in eth.data
            if not isinstance(eth.data, dpkt.ip.IP):
                # print 'Non IP Packet type not supported %s\n' % eth.data.__class__.__name__
                continue
            ip = eth.data
            
        # flow id with src & dst
        flowid = ip.src+"|"+ip.dst

        # get interval
        if flowid in timestamp:
            prev_ts = timestamp[flowid]
        else:
            prev_ts = 0
        interval = ts-prev_ts 

        if interval > 0 and prev_ts != 0:
            if interval > args.ub:
                if args.ub in interval_dist:
                    interval_dist[args.ub]=interval_dist[args.ub]+1
                else:
                    interval_dist[args.ub]=1
            elif interval < 1:
                if round(interval,1) in interval_dist:
                    interval_dist[round(interval,1)]=interval_dist[round(interval,1)]+1
                else:
                    interval_dist[round(interval,1)]=1
            else:
                if round(interval) in interval_dist:
                    interval_dist[round(interval)]=interval_dist[round(interval)]+1
                else:
                    interval_dist[round(interval)]=1


        # update lastseen 
        timestamp[flowid]=ts 

    f.close()
    

    # Print status
    print ("#Source pcap filename:", pcap_file)
    print ("#Upperbound: ", args.ub)
    print ("#CDF mode: ", args.cdf)
    print ("#Raw mode: ", raw) 

    # Print dist sorted order
    total=0
    curr=0
    if args.cdf is True:
        # get all
        for val in interval_dist.values() :
            total=total+val 
        # print 
        for interval in sorted(interval_dist.keys()) :
            curr=curr+interval_dist[interval]
            print interval , float(curr)/float(total)
    else:
        for interval in sorted(interval_dist.keys()) :
            print interval , interval_dist[interval]

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Reading pcap from RAW IP, distribution of packet inter-arrival.")
    # arguments
    parser.add_argument('--file', help="pcap filename", type=str, action="store", required=True)
    # parser.add_argument('--size', help="table size", type=int, action="store", required=False, default=1024)
    # parser.add_argument('--ltt', help="long-term timeout (sec)", type=float, action="store", required=False, default=50)
    parser.add_argument('--ub', help="upperbound", type=int, action="store", default=100)
    parser.add_argument('--raw', help="raw IP pcap mode", action="store_true")
    parser.add_argument('--cdf', help="CDF output format", action="store_true")

    args=parser.parse_args()

    # read & process the target pcap
    # check file
    if not os.path.exists(args.file):
        parser.print_help()
        parser.exit(1)
    # pass into function
    process_pcap(args)

