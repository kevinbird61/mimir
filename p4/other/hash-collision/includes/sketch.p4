#ifndef __SKETCH__
#define __SKETCH__

#include "headers.p4"

#define TABLE_SLOT 1024

control traffic_sketch(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // record 
    //register<bit<32>>(TABLE_SLOT) Flow_t;   // flow table
    register<bit<32>>(TABLE_SLOT) FlowSrcIP;
    register<bit<32>>(TABLE_SLOT) FlowDstIP;
    //register<bit<16>>(TABLE_SLOT) Port_t;   // port table
    register<bit<16>>(TABLE_SLOT) FlowSrcPort;
    register<bit<16>>(TABLE_SLOT) FlowDstPort;

    // collision count for IP
    register<bit<32>>(1)          IP_C_cnt;
    register<bit<32>>(1)          Port_C_cnt;

    apply {
        bit<32> srcIP;
        bit<32> dstIP;
        bit<16> srcPort;
        bit<16> dstPort;

        // Get hash id 
        // FIXME: using register to set the using algorithm
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

        FlowSrcIP.read(srcIP, metadata.flow_id);
        FlowDstIP.read(dstIP, metadata.flow_id);

        if(hdr.tcp.isValid() || hdr.udp.isValid()){
            // Get port id
            hash(
                metadata.port_id,
                HashAlgorithm.crc32,
                (bit<32>)0,
                {
                    metadata.l4_srcPort,
                    metadata.l4_dstPort
                },
                (bit<32>)TABLE_SLOT
            );

            FlowSrcPort.read(srcPort, metadata.port_id);
            FlowDstPort.read(dstPort, metadata.port_id);

        } else {
            srcPort = 16w0;
            dstPort = 16w0;
        }

        @atomic{
            bit<32> cnt;
            // IP collision
            if(srcIP != 32w0 && dstIP != 32w0){ // make sure it is valid
                if(srcIP != hdr.ipv4.srcAddr || dstIP != hdr.ipv4.dstAddr){
                    IP_C_cnt.read(cnt, 0);
                    cnt = cnt + 1;
                    IP_C_cnt.write(0, cnt);
                }
            }
            
            // Port collision
            if(srcPort != 16w0 && dstPort != 16w0){ // make sure it is valid
                if(srcPort != metadata.l4_srcPort || dstPort != metadata.l4_dstPort){
                    Port_C_cnt.read(cnt, 0);
                    cnt = cnt + 1;
                    Port_C_cnt.write(0, cnt);
                }
            }

            // write back 
            FlowSrcIP.write(metadata.flow_id, hdr.ipv4.srcAddr);
            FlowDstIP.write(metadata.flow_id, hdr.ipv4.dstAddr);

            FlowSrcPort.write(metadata.port_id, metadata.l4_srcPort);
            FlowDstPort.write(metadata.port_id, metadata.l4_dstPort);
        }
    }
}

#endif