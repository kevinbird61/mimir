#ifndef __REPORT__
#define __REPORT__

/* using digest to send the report to controller */

#include "headers.p4"

// report structure
struct report_digest_t {
    bit<32> srcIP;
    bit<32> dstIP;
    bit<5>  report_bitmap;
}

control report(
    inout headers_t             hdr,
    inout metadata_t            metadata,
    inout standard_metadata_t   standard_metadata
){
    register<bit<5>>(TABLE_SLOT) report_bitmap;

    apply {
        // check the value (previous bitmap)
        // -> only report the flow that change it's report val
        bit<5> prev_report_val;
        report_bitmap.read(prev_report_val, metadata.flow_id);
        // only need to report when report_bitmap > 1
        if(metadata.report_bitmap>1){
            if(prev_report_val==metadata.report_bitmap){
                // do nothing (don't report)
                // same situation to previous state
            }else{
                // report/drop/rate limit

                // solution#1 - report (using digest method)
                digest<report_digest_t>(
                    (bit<32>)1024,
                    {
                        hdr.ipv4.srcAddr,
                        hdr.ipv4.dstAddr,
                        metadata.report_bitmap
                    });
                
                // TODO: solution#2 - rate limiting
                // TODO: solution#3 - drop

                // write back into report_bitmap
                report_bitmap.write(metadata.flow_id, metadata.report_bitmap);
            }
        }
    }
}

#endif