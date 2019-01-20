#ifndef __HEADERS__
#define __HEADERS__

#include "def/enum.p4"
#include "def/l2.p4"
#include "def/l3.p4"
#include "def/l4.p4"
#include "def/l567.p4"

#define CPU_PORT 255

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
}

// packet out 
@controller_header("packet_out")
header packet_out_header_t {
    bit<16>  egress_port;
}

// header struct for packet
struct headers_t {
    packet_out_header_t     packet_out;
    packet_in_header_t      packet_in;
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    tcp_t                   tcp;
    udp_t                   udp;
}

// metadata inside switch pipeline
struct metadata_t {
    bit<16>     l4_srcPort;
    bit<16>     l4_dstPort;

    bit<1>      send_to_cpu;

    bit<32>     flow_id;
    bit<32>     port_id;

    bit<1>      report_flag;
}

#endif