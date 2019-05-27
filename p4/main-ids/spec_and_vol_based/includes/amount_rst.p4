#ifndef __RST__
#define __RST__

/* detect whether current flow is surpass RST threshold */

#include "headers.p4"

#define RST_THRESHOLD 16w50

control amount_rst(
    in bit<1>                   ctrl,
    inout headers_t             hdr,
    inout metadata_t            metadata,
    inout standard_metadata_t   standard_metadata
){
    register<bit<16>>(TABLE_SLOT) rst;

    apply {
        // control flag
        if(ctrl==1w0){
            // 0: update
            bit<16> prev_rst;
            rst.read(prev_rst, metadata.flow_id);
            rst.write(metadata.flow_id, prev_rst);
        } else {
            // 1: detect
            bit<16> prev_rst;
            rst.read(prev_rst, metadata.flow_id);
            // check 
            if(prev_rst > RST_THRESHOLD){
                metadata.report_bitmap = metadata.report_bitmap | 16;
            }
        }
    }
}

#endif 