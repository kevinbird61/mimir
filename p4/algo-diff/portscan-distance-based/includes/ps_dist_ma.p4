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

#define TABLE_SLOT 1024

control portscan_d(
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

    // threshold 
    register<bit<32>>(1) WeightThres;          // Threshold of distance volume (Using simple_switch_CLI)

    // report cnt
    register<bit<32>>(1) ReportCnt;

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
            // xxhash only (can't place in action block)
            //bit<32> acc;
            //xxhash_init.apply((bit<32>)hdr.ipv4.srcAddr, 32w0, acc);
            //xxhash.apply((bit<32>)hdr.ipv4.dstAddr, acc, 0, TABLE_SLOT, metadata.flow_id);
        
            get_OD_pair_id();
            @atomic{
                // Get the values from volume-based table
                bit<32> pre_portstatus;
                bit<32> pre_weight;
                PortDist.read(pre_portstatus, metadata.flow_id);
                DistWeight.read(pre_weight, metadata.flow_id);

                // Count the Hamming distance between port dist
                bit<32> weight;
                pre_portstatus = pre_portstatus ^ metadata.port_id; // now pre_portstatus = distance
                popcount.apply(pre_portstatus, weight); // weight will > 0 if pre_portstatus is diff from port_id
                // Add wegiht to pre_weight
                pre_weight = pre_weight + weight;

                // Check the weight
                bit<32> c_thres;
                // WeightThres.read(c_thres, 0); 
                c_thres = 32w2131;
                if(pre_weight > c_thres && c_thres > 0){
                    // if surpass the threshold, then report_flag=1 
                    // metadata.report_flag = 1w1;
                    bit<32> rcnt;
                    ReportCnt.read(rcnt, 0);
                    ReportCnt.write(0, rcnt+1);
                    // FIXME: currently drop the packet 
                    mark_to_drop();
                    // Clean weight 
                    pre_weight = 0;
                }
                DistWeight.write(metadata.flow_id, pre_weight);
                PortDist.write(metadata.flow_id, metadata.port_id); // only record the latest active one
            }
        }
    }
}

#endif 