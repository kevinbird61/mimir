#ifndef __SKETCH__
#define __SKETCH__

#include "headers.p4"
#include "hash.p4"      // our custom hash function
#include "xxhash.p4"    // xxhash

#define TABLE_SLOT 256

control custom_sketch(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // custom hash function
    djb2_32_init() djb2_init;
    djb2_32()      djb2;
    jenkins_32_init() jenkins_init;
    jenkins_32()      jenkins;
    sdbm_32_init()    sdbm_init;
    sdbm_32()         sdbm;
    loselose_32_init()  loselose_init;
    loselose_32()       loselose;
    xxhash32_init()     xxhash_init;
    xxhash32()          xxhash;

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

    // debug
    register<bit<32>>(1)          flow_id;
    register<bit<32>>(1)          port_id;

    apply {
        bit<32> srcIP;
        bit<32> dstIP;
        bit<16> srcPort;
        bit<16> dstPort;

        // Get hash id 
        // djb2_init.apply((bit<32>)hdr.ipv4.srcAddr, 0, TABLE_SLOT, metadata.flow_id);
        // djb2.apply((bit<32>)hdr.ipv4.dstAddr, 0, TABLE_SLOT, metadata.flow_id);
        // jenkins_init.apply((bit<32>)hdr.ipv4.srcAddr, 0, TABLE_SLOT, metadata.flow_id);
        // jenkins.apply((bit<32>)hdr.ipv4.dstAddr, 0, TABLE_SLOT, metadata.flow_id);
        // sdbm_init.apply((bit<32>)hdr.ipv4.srcAddr, 0, TABLE_SLOT, metadata.flow_id);
        // sdbm.apply((bit<32>)hdr.ipv4.dstAddr, 0, TABLE_SLOT, metadata.flow_id);
        // loselose_init.apply((bit<32>)hdr.ipv4.srcAddr, 0, TABLE_SLOT, metadata.flow_id);
        // loselose.apply((bit<32>)hdr.ipv4.dstAddr, 0, TABLE_SLOT, metadata.flow_id);
        
        // xxhash only
        bit<32> acc;
        xxhash_init.apply((bit<32>)hdr.ipv4.srcAddr, 32w0, acc);
        xxhash.apply((bit<32>)hdr.ipv4.dstAddr, acc, 0, TABLE_SLOT, metadata.flow_id);

        FlowSrcIP.read(srcIP, metadata.flow_id);
        FlowDstIP.read(dstIP, metadata.flow_id);

        if(hdr.tcp.isValid() || hdr.udp.isValid()){
            // Get port id
            // djb2_init.apply((bit<32>)metadata.l4_srcPort, 0, TABLE_SLOT, metadata.port_id);
            // djb2.apply((bit<32>)metadata.l4_dstPort, 0, TABLE_SLOT, metadata.port_id);
            // jenkins_init.apply((bit<32>)metadata.l4_srcPort, 0, TABLE_SLOT, metadata.port_id);
            // jenkins.apply((bit<32>)metadata.l4_dstPort, 0, TABLE_SLOT, metadata.port_id);
            // sdbm_init.apply((bit<32>)metadata.l4_srcPort, 0, TABLE_SLOT, metadata.port_id);
            // sdbm.apply((bit<32>)metadata.l4_dstPort, 0, TABLE_SLOT, metadata.port_id);
            // loselose_init.apply((bit<32>)metadata.l4_srcPort, 0, TABLE_SLOT, metadata.port_id);
            // loselose.apply((bit<32>)metadata.l4_dstPort, 0, TABLE_SLOT, metadata.port_id);

            xxhash_init.apply((bit<32>)metadata.l4_srcPort, 32w0, acc);
            xxhash.apply((bit<32>)metadata.l4_dstPort, acc, 0, TABLE_SLOT, metadata.port_id);

            FlowSrcPort.read(srcPort, metadata.port_id);
            FlowDstPort.read(dstPort, metadata.port_id);

        } else {
            srcPort = 16w0;
            dstPort = 16w0;
        }

        flow_id.write(0, metadata.flow_id);
        port_id.write(0, metadata.port_id);

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