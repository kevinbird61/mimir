#ifndef __FILTER__
#define __FILTER__

#include "headers.p4"

control netflow_filter(
    inout headers_t hdr,
    inout metadata_t metadata, 
    inout standard_metadata_t standard_metadata
){

    /* pass filter */
    action pass_filter(){
        // set the flag to 1
        metadata.pass_filter = 8w1;
    }

    table tb_filter{
        key = {
            hdr.ipv4.dstAddr: ternary;
            hdr.ipv4.srcAddr: ternary;
            hdr.ethernet.etherType: ternary;
        }
        actions = {
            NoAction;
            pass_filter;
        }
        size=1024;
        default_action=NoAction();
    }

    apply {
        tb_filter.apply();
    }
}

#endif