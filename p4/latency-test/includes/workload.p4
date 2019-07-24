#ifndef __WORKLOAD__
#define __WORKLOAD__

#include "headers.p4"

control dump(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // dump 
    register<bit<16>>(1) dump_op_1;
    register<bit<16>>(1) dump_op_2;

    apply {
        // execute the additional write/read operation
        bit<16> tmp;
        // 2R, 2W
        dump_op_1.read(tmp, 0);
        dump_op_1.write(0, tmp+1);
        dump_op_2.read(tmp, 0);
        dump_op_2.write(0, tmp+1);
        // 2R, 2W
        dump_op_1.read(tmp, 0);
        dump_op_1.write(0, tmp+1);
        dump_op_2.read(tmp, 0);
        dump_op_2.write(0, tmp+1);
        // 2R, 2W
        dump_op_1.read(tmp, 0);
        dump_op_1.write(0, tmp+1);
        dump_op_2.read(tmp, 0);
        dump_op_2.write(0, tmp+1);
        // 2R, 2W
        dump_op_1.read(tmp, 0);
        dump_op_1.write(0, tmp+1);
        dump_op_2.read(tmp, 0);
        dump_op_2.write(0, tmp+1);
        // 2R, 2W
        dump_op_1.read(tmp, 0);
        dump_op_1.write(0, tmp+1);
        dump_op_2.read(tmp, 0);
        dump_op_2.write(0, tmp+1);
    }
}

control workload_full(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    dump() work;

    apply {
        work.apply(hdr, metadata, standard_metadata);
    }
}

control workload(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // control traffic size need to process
    register<bit<16>>(1) pktcnt; 
    register<bit<16>>(1) total;

    // dump 
    dump() work;

    apply {
        // read pktcnt (sample or not)
        bit<16> curr_pktcnt;
        bit<16> total_pktcnt;
        pktcnt.read(curr_pktcnt, 0);
        total.read(total_pktcnt, 0);

        // First 20, workload=full
        // if(total_pktcnt < 100) {
            // work.apply(hdr, metadata, standard_metadata); // 30R,30W
        //} else if(total_pktcnt >= 100 && total_pktcnt < 200) {
            // 20~40, workload=3/4
            /*
            if(curr_pktcnt >= 4)
            {
                curr_pktcnt=0;
            } else {
                work.apply(hdr, metadata, standard_metadata);
                curr_pktcnt=curr_pktcnt+1;
            }
            // write back
            pktcnt.write(0, curr_pktcnt);
            */
            
        // } else if(total_pktcnt >= 200 && total_pktcnt < 300) {
            // workload=1/2
            /*
            if(curr_pktcnt >= 1)
            {
                curr_pktcnt=0;
            } else {
                work.apply(hdr, metadata, standard_metadata);
                curr_pktcnt=curr_pktcnt+1;
            }
            // write back
            pktcnt.write(0, curr_pktcnt);
            */
        // } else {
            // do nothing
        // }
            /*if(curr_pktcnt >= 4)
            {
                work.apply(hdr, metadata, standard_metadata);
                curr_pktcnt=0;
            } else {
                curr_pktcnt=curr_pktcnt+1;
            }
            // write back
            pktcnt.write(0, curr_pktcnt);
            */

        // test of amount of operation 
        // work.apply(hdr, metadata, standard_metadata);
        // work.apply(hdr, metadata, standard_metadata);
        // work.apply(hdr, metadata, standard_metadata);
        //work.apply(hdr, metadata, standard_metadata);
        // work.apply(hdr, metadata, standard_metadata);

        total.write(0, total_pktcnt+1);
        
    }
}



#endif