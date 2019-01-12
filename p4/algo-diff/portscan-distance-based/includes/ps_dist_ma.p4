#ifndef __PORTSCAN_DISTANCE_MA__
#define __PORTSCAN_DISTANCE_MA__

/* 
    Portscan distance-based with moving average
    - using MA (SMA/WMA) as its real "distance" between each change
    - using several K-V table as sketches (each one has uniq-hash)
*/

#include "headers.p4"
#include "xxhash.p4"
#include "hamming_weight.p4"

#define TABLE_SLOT 128

control portscan_ma_stage1(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // xxhash     
    xxhash32_init()     xxhash_init;
    xxhash32()          xxhash;

    // Hamming weight
    popcount32_native() popcount;

    register<bit<32>>(TABLE_SLOT) PortDist; // Port Distribution
    register<bit<32>>(TABLE_SLOT) DistWeight;  // (Hamming) Distance volume (the amount of changing)

    action get_OD_pair_id(){
        // get hash id 
        hash(metadata.flow_id, 
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            (bit<32>)TABLE_SLOT);
        
        // Get hash value of port (src, dst)
        // aim to represent the port distribution
        hash(metadata.port_id, 
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                metadata.l4_srcPort,
                metadata.l4_dstPort
            },
            (bit<32>)65536);
    }

    apply {
        if(hdr.tcp.isValid() || hdr.udp.isValid()){
            get_OD_pair_id();
            @atomic{
                // Get the values from volume-based table
                bit<32> pre_portstatus;
                PortDist.read(pre_portstatus, metadata.flow_id);

                // if current stage entry is empty
                if(pre_portstatus == 0){
                    PortDist.write(metadata.flow_id, metadata.port_id);
                } else {
                    // Count the Hamming distance between port dist
                    bit<32> weight;
                    weight = pre_portstatus ^ metadata.port_id; // now pre_portstatus = distance
                    if(weight > 0){
                        // popout is available
                        metadata.popout = pre_portstatus;
                        // Update PortDistance to new one
                        PortDist.write(metadata.flow_id, metadata.port_id);
                        // weight will > 0 if pre_portstatus is diff from port_id
                        // , also reuse variable
                        popcount.apply(weight, pre_portstatus); 
                        // pre_status now represent the distance change
                        metadata.avail_cnt = metadata.avail_cnt+1;
                        metadata.amd = metadata.amd + pre_portstatus;
                    } else {
                        // not change, do nothing
                        metadata.popout = 0;
                    }
                }
            }
        }
    }
}

control portscan_ma_stage2(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // xxhash     
    xxhash32_init()     xxhash_init;
    xxhash32()          xxhash;
    // Hamming weight
    popcount32_native() popcount;

    register<bit<32>>(TABLE_SLOT) PortDist; // Port Distribution

    apply {
        if(metadata.popout == 0){
            // without any popout value, skip this stage, do nothing
        } else {
            // write this value into PortDist
            @atomic {
                bit<32> pre_portstatus;
                // FIXME: 
                // In sketch algorithm, need to use a different hashing function. 
                PortDist.read(pre_portstatus, metadata.flow_id);
                if(pre_portstatus == 0){
                    // place the popout value into this stage
                    PortDist.write(metadata.flow_id, metadata.popout);
                    // clear
                    metadata.popout = 0;
                } else {
                    bit<32> weight;
                    weight = pre_portstatus ^ metadata.popout;
                    if(weight > 0){
                        // Update PortDist
                        PortDist.write(metadata.flow_id, metadata.popout);
                        // popout 
                        metadata.popout = pre_portstatus;
                        // weight will > 0 if pre_portstatus is diff from port_id
                        // , also reuse variable
                        popcount.apply(weight, pre_portstatus); 
                        // pre_status now represent the distance change
                        metadata.avail_cnt = metadata.avail_cnt+1;
                        metadata.amd = metadata.amd + pre_portstatus;
                    } else {
                        // not change, do nothing
                        metadata.popout = 0;
                    }
                }

            }
        }
    }
}

// final stage
control portscan_ma_stage_fin(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    register<bit<32>>(TABLE_SLOT) DistWeight;  // (Hamming) Distance volume (the amount of changing)

    apply {
        /* 
            metadata.avail_cnt  : available counter (e.g. how many stage has changed)
            metadata.amd        : total moving distance
        */
        @atomic{
            // Get its MA
            // metadata.amd = metadata.amd / metadata.avail_cnt; // dont support divide, need to use another way to measure, or just do nothing
            DistWeight.write(metadata.flow_id, metadata.amd);

            // TODO:
            // If MA > threshold, send back to controller
        }
    }
}


#endif 