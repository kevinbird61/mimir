#ifndef __BASELINE_PORTSCAN_D__
#define __BASELINE_PORTSCAN_D__

#include "headers.p4"
#include "hamming_weight.p4"

#define TABLE_SLOT 512 

control portscan_d(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    popcount32_native() popcount;

    register<bit<32>>(TABLE_SLOT) PortDist;
    register<bit<32>>(1)          TotalWeight;

    action get_OD_pair_id(){
        // get flow id
        hash(metadata.flow_id,
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            (bit<32>)TABLE_SLOT);
        // get port id
        hash(metadata.port_id,
            HashAlgorithm.crc16,
            32w0,
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
                bit<32> pre_weight;
                PortDist.read(pre_portstatus, metadata.flow_id);
                TotalWeight.read(pre_weight, 0);

                // Count the Hamming distance between port dist
                bit<32> weight;
                pre_portstatus = pre_portstatus ^ metadata.port_id; // now pre_portstatus = distance
                popcount.apply(pre_portstatus, weight); // weight will > 0 if pre_portstatus is diff from port_id
                // Add wegiht to pre_weight
                pre_weight = pre_weight + weight;
                
                // Update
                TotalWeight.write(0, pre_weight);
                PortDist.write(metadata.flow_id, metadata.port_id); // only record the latest active one
            }
        }
    }
}

#endif