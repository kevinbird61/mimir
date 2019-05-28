#ifndef __UNIQUE_DPORT__
#define __UNIQUE_DPORT__

/* detect whether current flow is suprpass unique dport threshold */

#include "../headers.p4"

#define DPORT_THRESHOLD 1000

control unique_dport(
    in bit<1>                   ctrl,
    inout headers_t             hdr,
    inout metadata_t            metadata,
    inout standard_metadata_t   standard_metadata
){
    register<bit<16>>(TABLE_SLOT) prev_dport;
    // 32bits size per entry (the value in this module is bigger)
    // (although you can still use 16bits)
    register<bit<32>>(TABLE_SLOT) dport;

    apply{
        // control flag
        if(ctrl== 0){
            // 0: update
            bit<16> prev_dport_val;
            bit<32> dport_cnt;
            prev_dport.read(prev_dport_val, metadata.flow_id);
            dport.read(dport_cnt, metadata.flow_id);
            // compare with current dst port
            if(metadata.l4_dstPort != prev_dport_val){
                dport.write(metadata.flow_id, dport_cnt+1);
            }
            // update prev port
            prev_dport.write(metadata.flow_id, metadata.l4_dstPort);
        } else {
            // 1: detect
            bit<32> dport_cnt;
            dport.read(dport_cnt, metadata.flow_id);
            // check
            if(dport_cnt > DPORT_THRESHOLD){
                metadata.report_bitmap = metadata.report_bitmap | 8;
            }
        }
    }
}

#endif 