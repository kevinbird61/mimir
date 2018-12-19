#ifndef __SAMPLING__
#define __SAMPLING__

#include "headers.p4"

#define TABLE_SLOT 128

control netflow_sampling(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    /*
        using register to maintain sampling table

        | key       | value         |
        | ========= | ============= |

        LastSeen:
        | Flow ID | LastSeen    |
        | <hash>  | <timestamp> | bit<48>

    */
    register<bit<48>>(TABLE_SLOT) LastSeen;
    register<bit<48>>(1)          DeltaTime_Threshold;

    action get_hashkey(){
        // Get index (Using 5 tuple)
        hash(
            metadata.flow_id, 
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                metadata.l4_srcPort,
                metadata.l4_dstPort
            },
            (bit<32>)TABLE_SLOT
        );
    }

    action update_ts(){
        // update time stamp 
        LastSeen.read(metadata.last_seen_val, metadata.flow_id);
        DeltaTime_Threshold.read(metadata.delta_time_val, 0);

        metadata.last_seen_val = standard_metadata.ingress_global_timestamp - metadata.last_seen_val;

        metadata.pass_sampling = ( metadata.last_seen_val > metadata.delta_time_val ? 8w1 : 8w0 );

        // then update last seen
        LastSeen.write(metadata.flow_id, standard_metadata.ingress_global_timestamp);
    }

    apply {
        // check if current packet is passing filter block
        if(metadata.pass_filter == 8w1){
            get_hashkey();
            update_ts();
        }
    }
}

#endif