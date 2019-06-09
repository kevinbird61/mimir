#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, grpc, os, sys
from time import sleep
from scapy.all import *

# set our lib path
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        '../../p4/utils/'))

SWITCH_TO_HOST_PORT = 1
SWITCH_TO_SWITCH_PORT = 2

# And then we import
import p4runtime_lib.bmv2
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper

def writeForwardRules(p4info_helper,ingress_sw,
    dst_eth_addr,port,dst_ip_addr):
    """
        Install rules:
        做到原本 sx-runtime.json 的工作
            p4info_helper:  the P4Info helper
            ingress_sw:     the ingress switch connection
            dst_eth_addr:   the destination IP to match in the ingress rule
            port:           port of switch
            dst_ip_addr:    the destination Ethernet address to write in the egress rule
    """

    # 1. Ingress rule
    table_entry = p4info_helper.buildTableEntry(
        table_name="basic_tutorial_ingress.ipv4_forwarding.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": (dst_ip_addr,16)
        },
        action_name="basic_tutorial_ingress.ipv4_forwarding.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": port
        })
    # write into ingress of target sw
    ingress_sw.WriteTableEntry(table_entry)
    print "Installed ingress forward rule on %s" % ingress_sw.name

def writeARPReply(p4info_helper, sw, in_port, dst_eth_addr, port=None):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.arp.arp_exact",
        match_fields = {
            "standard_metadata.ingress_port": in_port,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name = "basic_tutorial_ingress.arp.arp_reply",
        action_params = {
            "port": port
        })
    sw.WriteTableEntry(table_entry)
    print "Installed ARP Reply rule via P4Runtime."

def writeARPFlood(p4info_helper, sw, in_port, dst_eth_addr, port=None):
    table_entry = p4info_helper.buildTableEntry(
        table_name = "basic_tutorial_ingress.arp.arp_exact",
        match_fields = {
            "standard_metadata.ingress_port": in_port,
            "hdr.ethernet.dstAddr": dst_eth_addr
        },
        action_name = "basic_tutorial_ingress.arp.flooding",
        action_params = {
        }
    )
    sw.WriteTableEntry(table_entry)
    print "Installed ARP Flooding rule via P4Runtime."

def printGrpcError(e):
    print "gRPC Error: ", e.details(),
    status_code = e.code()
    print "(%s)" % status_code.name,
    # detail about sys.exc_info - https://docs.python.org/2/library/sys.html#sys.exc_info
    traceback = sys.exc_info()[2]
    print "[%s:%s]" % (traceback.tb_frame.f_code.co_filename, traceback.tb_lineno)

def SendDigestEntry(p4info_helper, sw, max_timeout_ns, max_list_size, ack_timeout_ns, digest_name=None):
    digest_entry = p4info_helper.buildDigestEntry(max_timeout_ns=max_timeout_ns, max_list_size=max_list_size, ack_timeout_ns=ack_timeout_ns, digest_name=digest_name)
    sw.WriteDigestEntry(digest_entry)
    print "Sent DigestEntry via P4Runtime."

def byte_pbyte(data):
    # check if there are multiple bytes
    if len(str(data)) > 1:
        # make list all bytes given
        msg = list(data)
        # mark which item is being converted
        s = 0
        for u in msg:
            # convert byte to ascii, then encode ascii to get byte number
            u = str(u).encode("hex")
            # make byte printable by canceling \x
            u = "\\x"+u
            # apply coverted byte to byte list
            msg[s] = u
            s = s + 1
        msg = "".join(msg)
    else:
        msg = data
        # convert byte to ascii, then encode ascii to get byte number
        msg = str(msg).encode("hex")
        # make byte printable by canceling \x
        msg = "\\x"+msg
    # return printable byte
    return msg

def prettify(mac_string):
    return ':'.join('%02x' % ord(b) for b in mac_string)

def IPv4_prettify(ipv4):
    return ':'.join('%d' % ord(b) for b in ipv4)

def Var_prettify(var):
    return ord(var)

def main(p4info_file_path, bmv2_file_path):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)
    # global
    report_list = {}
    port_map = {}
    arp_rules = {}
    flag = 0
    bcast = "ff:ff:ff:ff:ff:ff"

    try:
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file="s1-runtime-requests.txt")

        s1.MasterArbitrationUpdate()

        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info, bmv2_json_file_path=bmv2_file_path)
        print "Installed P4 Program using SetForardingPipelineConfig on s1"

        # Send digest entry
        """
         - max_timeout_ns=1000000000 (1s)
         - ack_timeout_ns=1000000000 (1s)
        """
        SendDigestEntry(p4info_helper, sw=s1, max_timeout_ns=0, max_list_size=1, ack_timeout_ns=0, digest_name="report_digest_t")

        # Monitoring (receive DigestMessage from s1)
        while True: 
            digests = s1.DigestList()
            if digests.WhichOneof('update')=='digest':
                print("Received DigestList message")
                """
                    Digest format:
                    * uint32 digest_id 
                    * uint64 list_id 
                    * repeated P4Data data 
                    * int64 timestamp 
                """
                digest = digests.digest
                print "===============================" 
                print "Digest ID: ", digest.digest_id 
                print "List ID: ", digest.digest_id
                # print "[Raw]Digest msg: ", digest.data 
                digest_message_list = digest.data   
                for members in digest_message_list:
                    #print members
                    if members.WhichOneof('data')=='struct':
                        # ipv4 srcAddr
                        #if members.struct.members[0].WhichOneof('data') == 'bitstring':
                        #    print members.struct.members[0].bitstring
                        # ipv4 dstAddr
                        #if members.struct.members[1].WhichOneof('data') == 'bitstring':
                        #    print members.struct.members[1].bitstring
                        # report val
                        #if members.struct.members[2].WhichOneof('data') == 'bitstring':
                        #    print members.struct.members[2].bitstring
                        # create one entry for it
                        print Var_prettify(members.struct.members[2].bitstring)
                        flowpair=IPv4_prettify(members.struct.members[0].bitstring),"->",IPv4_prettify(members.struct.members[1].bitstring)
                        print flowpair
                        if flowpair in report_list:
                            report_list[flowpair]=report_list[flowpair]+1
                        else:
                            report_list[flowpair]=1
            packetin = s1.PacketIn()
            if packetin.WhichOneof('update')=='packet':
                # print("Received Packet-in\n")
                packet = packetin.packet.payload
                pkt = Ether(_pkt=packet)
                metadata = packetin.packet.metadata 
                for meta in metadata:
                    metadata_id = meta.metadata_id 
                    value = meta.value 

                pkt_eth_src = pkt.getlayer(Ether).src 
                pkt_eth_dst = pkt.getlayer(Ether).dst 
                ether_type = pkt.getlayer(Ether).type 

                if ether_type == 2048 or ether_type == 2054:
                    port_map.setdefault(pkt_eth_src, value)
                    arp_rules.setdefault(value, [])

                    if pkt_eth_dst == bcast:
                        if bcast not in arp_rules:
                            writeARPFlood(p4info_helper, sw=s1, in_port=value, dst_eth_addr=bcast)
                            arp_rules[value].append(bcast)
                        # build packetout
                        packetout = p4info_helper.buildPacketOut(
                            payload = packet,
                            metadata = {
                                1: "\000\000",
                                2: "\000\001"
                            }
                        )
                        s1.PacketOut(packetout)
                    else:
                        if pkt_eth_dst not in arp_rules[value]:
                            writeARPReply(p4info_helper, sw=s1, in_port=value, dst_eth_addr=pkt_eth_dst, port=port_map[pkt_eth_dst])
                            arp_rules[value].append(pkt_eth_dst)
                        if pkt_eth_src not in arp_rules[port_map[pkt_eth_dst]]:
                            writeARPReply(p4info_helper, sw=s1, in_port=port_map[pkt_eth_dst], dst_eth_addr=pkt_eth_src, port=port_map[pkt_eth_src])
                            arp_rules[port_map[pkt_eth_dst]].append(pkt_eth_src)
                        
                        packet_out = p4info_helper.buildPacketOut(
                            payload = packet,
                            metadata = {
                                1: port_map[pkt_eth_dst],
                                2: "\000\000"
                            }
                        )
                        s1.PacketOut(packet_out)
                    print "Finished PacketOut."
                    print "========================="
                    print "port_map:%s" % port_map
                    print "arp_rules:%s" % arp_rules
                    print "=========================\n"

    except KeyboardInterrupt:
        # using ctrl + c to exit
        print "Shutting down."
    except grpc.RpcError as e:
        printGrpcError(e)

    # print summary
    for elem in report_list:
        print (elem,": ",report_list[elem])


    # Then close all the connections
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    """ Simple P4 Controller
        Args:
            p4info:     指定 P4 Program 編譯產生的 p4info (PI 制定之格式、給予 controller 讀取)
            bmv2-json:  指定 P4 Program 編譯產生的 json 格式，依據 backend 不同，而有不同的檔案格式
     """

    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    # Specified result which compile from P4 program
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
            type=str, action="store", required=False,
            default="./simple.p4info")
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
            type=str, action="store", required=False,
            default="./simple.json")
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print "\np4info file not found: %s\nPlease compile the target P4 program first." % args.p4info
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print "\nBMv2 JSON file not found: %s\nPlease compile the target P4 program first." % args.bmv2_json
        parser.exit(1)

    # Pass argument into main function
    main(args.p4info, args.bmv2_json)