#ifndef __IDS__
#define __IDS__

#include "headers.p4"

// detection module
#include "frequency.p4"
#include "unique_dport.p4"
#include "amount_rst.p4"
// report (digest)
#include "report.p4"

#define TIMEOUT 100         // represent 0.1 sec 

control ids(
    inout headers_t hdr, 
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // create instances, and rename them into mod(N)
    frequency()     mod1;
    unique_dport()  mod4;
    amount_rst()    mod5;
    // report instance
    report()        mod_report;

    // lastseen timestamp (flow)
    register<bit<48>>(TABLE_SLOT) lastSeen;

    apply {
        // get flow id 
        hash(
            metadata.flow_id,
            HashAlgorithm.crc32,
            (bit<32>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            (bit<32>)TABLE_SLOT
        );

        // time interval checking
        bit<48> interval;
        bit<48> prev_ts;
        lastSeen.read(prev_ts, metadata.flow_id);
        // using ingress_global_timestamp as current_timestamp
        interval=(prev_ts== 48w0)?48w0:(standard_metadata.ingress_global_timestamp - prev_ts);
        // checking 
        if(interval > TIMEOUT){
            // timeout event (detection phase)
            // goto frequency module  
            mod1.apply(1w1, hdr, metadata, standard_metadata);
            // check report
            if((metadata.report_bitmap | 5w1)==5w1){
                // high frequency confirm
                // goto amount_rst module 
                mod5.apply(1w1, hdr, metadata, standard_metadata);
                // goto unique_dport module
                mod4.apply(1w1, hdr, metadata, standard_metadata);
            } else {
                // low frequency confirm 
                // goto unique_dport module
                mod4.apply(1w1, hdr, metadata, standard_metadata);
            }
        } else {
            // normal (sampled phase)
            // update each module (call same module, with different control flag)
            // - 0: update status
            // - 1: detection

            // update frequency 
            mod1.apply(1w0, hdr, metadata, standard_metadata);
            // update rst
            mod5.apply(1w0, hdr, metadata, standard_metadata);
            // update unique_dport
            mod4.apply(1w0, hdr, metadata, standard_metadata);
        }

        // report (base on report_bitmap)
        mod_report.apply(hdr, metadata, standard_metadata);
    }
}

#endif