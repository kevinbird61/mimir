#ifndef __DIGEST__
#define __DIGEST__

#include "headers.p4"

// digest information data structure
struct anomaly_candidate_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    // bit<32> hamming;
}

control send_to_controller(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    apply {
        /* using metadata.send_to_cpu flag */
        if(metadata.send_to_cpu==1w1){
            // then call digest method (pack)
            digest<anomaly_candidate_t>((bit<32>)1024,
                {
                    hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr
                });
        }
    }
}