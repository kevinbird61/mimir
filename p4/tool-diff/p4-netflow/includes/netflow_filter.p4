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

    /* simply using LPM (longest prefix matching) 
        to represent the filter functionality
    */
    table tb_simple_filter{
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            NoAction;
            pass_filter;
        }
        size=1024;
        // FIXME: Debug only 
        default_action=pass_filter();
    }

    apply {
        // complex filter
        tb_filter.apply();
        // simple filter (for minimal testcase)
        tb_simple_filter.apply();
    }
}

#endif