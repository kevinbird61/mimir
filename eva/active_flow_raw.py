#!/usr/bin/env python 

import argparse, os 
import dpkt 

def IPv4_prettify(ipv4):
    return ':'.join('%d' % ord(b) for b in ipv4)

def process_pcap(pcap_file):
    # read fuke
    f = open(pcap_file,'rb')
    pcap = dpkt.pcap.Reader(f)

    # global 
    start_ts=3444444444
    range_ts=1 #sec
    timeline={}
    # pktcnt
    total_pkt=0
    nonIP_pkt=0

    for ts, buf in pcap:
        """ read from ethernet
        #eth = dpkt.ethernet.Ethernet(buf)
        #ip = eth.data
        """

        if start_ts > ts:
            start_ts=ts # update start_ts (to mini. one)

        # read from raw IP 
        # using try/catch block to avoid error corruption
        total_pkt=total_pkt+1
        try:
            ip = dpkt.ip.IP(buf)
        except:
            nonIP_pkt=nonIP_pkt+1
            #print("Something else went wrong")
        #tcp = ip.data
        timeslot = round((ts-start_ts)/range_ts, 2)
        #print timeslot, ":", IPv4_prettify(ip.src), "<->", IPv4_prettify(ip.dst)

        flowid=IPv4_prettify(ip.src)+"|"+IPv4_prettify(ip.dst)

        # push into timeline 
        if timeslot in timeline: 
            # exist
            if flowid in timeline[timeslot]:
                timeline[timeslot][flowid]=timeline[timeslot][flowid]+1
            else: 
                timeline[timeslot][flowid]=1
        else:
            # not exist
            timeline[timeslot]={flowid: 1}

    f.close()
    
    # print with sorted order
    for ts in sorted(timeline.keys()) :
        print ts , len( timeline[ts] )
    # Print status
    print "#NonIP: ", nonIP_pkt, "; Total pktcnt: ", total_pkt
    print "#NonIP (in Raw IP): ", float(nonIP_pkt)/ float(total_pkt)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Reading pcap from RAW IP")
    # arguments
    parser.add_argument('--file', help="pcap filename", type=str, action="store", required=True)

    args=parser.parse_args()

    # read & process the target pcap
    # check file
    if not os.path.exists(args.file):
        parser.print_help()
        parser.exit(1)
    # pass into function
    process_pcap(args.file)

