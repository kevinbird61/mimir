#ifndef __REPORT__
#define __REPORT__

#include "headers.p4"

// for digest data structure 
// - which record the information of that packet
// - the essential part of data detection
struct flowCache_t {
    bit<16> ingress_port;

    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
    bit<8>  protocol;

    bit<16> srcPort;
    bit<16> dstPort;
    bit<6>  dscp;
}

control report(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // Then we use digest to send the information 
    // to our controller
    action send_to_cpu(){
        digest<flowCache_t>((bit<32>) 1024,
            {   
                (bit<16>)standard_metadata.ingress_port,

                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,

                metadata.l4_srcPort,
                metadata.l4_dstPort,
                hdr.ipv4.dscp
            });
    }

    apply {
        // if flowlet set this flag, then we can 
        // leverage digest mechanism to report 
        // this flow to controller
        if(metadata.send_to_cpu == 8w1){
            send_to_cpu();
        }
    }
}

#endif