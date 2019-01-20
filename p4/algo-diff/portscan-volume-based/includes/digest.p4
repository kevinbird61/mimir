#ifndef __DIGEST__
#define __DIGEST__

#include "headers.p4"

// digest information data structure
struct flowCache_digest_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
}

control send_to_controller(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    action send2cpu(){
        // call digest method (pack)
        digest<flowCache_digest_t>((bit<32>)1024,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            });
    }

    apply {
        /* using metadata.send_to_cpu flag */
        if(metadata.send_to_cpu==1w1){
            send2cpu();
        }
    }
}

#endif