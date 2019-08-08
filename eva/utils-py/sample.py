#!/usr/bin/env python 

"""
Compute the sample rate in MIMIR design (incompleted)
Python version.
"""

import socket
import argparse, os 
import dpkt 

# CRC
from PyCRC.CRC32 import CRC32
from PyCRC.CRCCCITT import CRCCCITT

def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def process_pcap(args):
    # read fuke
    f = open(args.file,'rb')
    pcap = dpkt.pcap.Reader(f)
    # ip list
    ip_list_f = open(args.anomaly, "r")
    anomaly_ip_list=[]
    for i in ip_list_f:
        # print i
        anomaly_ip_list.append(i)
    # global 
    timestamp = {}
    detection = 0
    anomalies = 0
    sampling = 0
    total = 0
    #
    total_pkt = 0
    nonIP_pkt = 0
    # selective sampling 
    selective_sampling = 0
    flow = {}

    for ts, buf in pcap:
        total=total+1
        # read from raw IP 
        # using try/catch block to avoid error corruption
        if args.raw is True:
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

        srcIP = inet_to_str(ip.src)
        dstIP = inet_to_str(ip.dst)

        # compare with sp 
        if interval > args.sp and prev_ts != 0:
            # detection
            detection=detection+1
        elif interval < args.sp:
            # sampling 
            if srcIP in anomaly_ip_list and dstIP in anomaly_ip_list:
                anomalies=anomalies+1
            sampling=sampling+1

        
        # update lastseen 
        timestamp[flowid]=ts 


    f.close()
    

    # Print status
    print "#Source pcap filename: ", args.file
    print "#Separated timeout: ", args.sp
    print "#Raw mode: ", args.raw
    print "#Sample rate: ", float(sampling)/float(total)
    print "#Sampled anomaly: ", float(anomalies)/float(sampling)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Reading pcap from RAW IP, distribution of packet inter-arrival.")
    # arguments
    parser.add_argument('--file', help="pcap filename", type=str, action="store", required=True)
    parser.add_argument('--sp', help="separated timeout (sec)", type=float, action="store", required=False, default=0.1)
    parser.add_argument('--raw', help="raw IP pcap mode", action="store_true")
    parser.add_argument('--anomaly', help="anomaly-related IP list", type=str, action="store", required=False, default="null")

    args=parser.parse_args()

    # read & process the target pcap
    # check file
    if not os.path.exists(args.file):
        parser.print_help()
        parser.exit(1)
    # pass into function
    process_pcap(args)

