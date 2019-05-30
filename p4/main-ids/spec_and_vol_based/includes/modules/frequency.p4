#ifndef __FREQ__
#define __FREQ__

/* detect whether current flow is high/low frequency */

#include "../headers.p4"

// FIXME: use register to make this timeout configurable
#define FREQ_THRESHOLD 10

control frequency(
    in bit<2>                   ctrl,
    inout headers_t             hdr,
    inout metadata_t            metadata,
    inout standard_metadata_t   standard_metadata
){
    register<bit<16>>(TABLE_SLOT) pktcnt;

    apply {
        // control flag
        if(ctrl==0){
            // 0: update
            bit<16> prev_pktcnt;
            pktcnt.read(prev_pktcnt, metadata.flow_id);
            // increase
            pktcnt.write(metadata.flow_id, prev_pktcnt+1);
        } else if(ctrl==1) {
            // 1: detect (check if it surpass threshold)
            // and update result in "metadata.report_bitmap"
            bit<16> prev_pktcnt;
            pktcnt.read(prev_pktcnt, metadata.flow_id);
            // check
            if(prev_pktcnt > FREQ_THRESHOLD){
                metadata.report_bitmap = metadata.report_bitmap | 1;
            } 
            // reset
            pktcnt.write(metadata.flow_id, 1);
        } else if(ctrl==2) {
            // 2: reset 
            pktcnt.write(metadata.flow_id, 1);
        }
    }
}

#endif