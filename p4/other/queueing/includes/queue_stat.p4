#ifndef __QUEUE_STAT__
#define __QUEUE_STAT__

#include "headers.p4"

// check enqueue stat
control enqueue(
    inout standard_metadata_t standard_metadata
){
    register<bit<19>>(1) enq_qd_stat;

    apply {
        @atomic {
            bit<32> ts;
            bit<19> qd;

            enq_qd_stat.read(qd, 0);
            if(qd != 19w0){
                qd = (qd + (standard_metadata.enq_qdepth))/2;
            } else {
                qd = (standard_metadata.enq_qdepth);
            }
            enq_qd_stat.write(0, qd);
        }
    }
}

// check dequeue stat
control dequeue(
    inout standard_metadata_t standard_metadata
){
    register<bit<32>>(1) deq_ts_stat;
    register<bit<19>>(1) deq_qd_stat;
    register<bit<32>>(1) max_deq_ts_stat;
    register<bit<19>>(1) max_deq_qd_stat;
    register<bit<32>>(1) min_deq_ts_stat;
    register<bit<19>>(1) min_deq_qd_stat;

    apply {
        @atomic {
            bit<32> ts;
            bit<32> max_ts;
            bit<32> min_ts;
            bit<19> qd;
            bit<19> max_qd;
            bit<19> min_qd;

            deq_ts_stat.read(ts, 0);
            deq_qd_stat.read(qd, 0);
            max_deq_ts_stat.read(max_ts, 0);
            max_deq_qd_stat.read(max_qd, 0);
            min_deq_ts_stat.read(min_ts, 0);
            min_deq_qd_stat.read(min_qd, 0);

            // Max queueing time
            if(standard_metadata.deq_timedelta > max_ts){
                max_ts = standard_metadata.deq_timedelta;
                max_deq_ts_stat.write(0, max_ts);
            }

            // Min queueing time
            if(standard_metadata.deq_timedelta < min_ts || min_ts == 0){
                min_ts = standard_metadata.deq_timedelta;
                min_deq_ts_stat.write(0, min_ts);
            }

            // Avg queueing time 
            if(ts != 32w0){
                ts = (ts + (standard_metadata.deq_timedelta)) /2;
            } else {
                ts = ((standard_metadata.deq_timedelta));
            }
            deq_ts_stat.write(0, ts);

            // Max queueing depth
            if(standard_metadata.deq_qdepth > max_qd){
                max_qd = standard_metadata.deq_qdepth;
                max_deq_qd_stat.write(0, max_qd);
            }

            // Max queueing depth
            if(standard_metadata.deq_qdepth < min_qd || min_qd == 0){
                min_qd = standard_metadata.deq_qdepth;
                min_deq_qd_stat.write(0, min_qd);
            }

            // Avg queueing length
            if(qd != 19w0){
                qd = (qd + (standard_metadata.deq_qdepth))/2;
            } else {
                qd = (standard_metadata.deq_qdepth);
            }
            deq_qd_stat.write(0, qd);
        }
    }
}

#endif