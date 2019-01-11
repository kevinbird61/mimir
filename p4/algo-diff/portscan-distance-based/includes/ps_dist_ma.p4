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

#endif 