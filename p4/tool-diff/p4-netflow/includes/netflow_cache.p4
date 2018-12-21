#ifndef __FLOWCACHE__
#define __FLOWCACHE__

#include "headers.p4"

#define CACHE_SLOT 128

// for digest data structure (which represent the basic unit in flowCache)
// - which record the information of that packet
// - the essential part of data detection
struct flowCache_t {
    bit<48> eth_srcAddr;
    bit<48> eth_dstAddr;
    bit<16> eth_type;

    bit<32> ipv4_srcAddr;
    bit<32> ipv4_dstAddr;
    bit<8>  protocol;

    bit<16> ingress_port;
}

control netflow_flowcache(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    /*
        Using digest mechanism as flowCache, the cache configuration is 
        set by DigestEntry.
        - max_timeout_ns
        - max_list_size
        - ack_timeout_ns

        According to NetFlow - FlowCache, the router will using 7 field to
        identify whether those packet belong to the same flow, which are:
        - ingress interface
        - source IP
        - destination IP
        - IP protocol number
        - TCP/UDP source port
        - TCP/UDP destination port
        - IP ToS
    */
    register<bit<32>>(CACHE_SLOT)   FlowCount;
    register<bit<32>>(1)            FlowCount_Threshold;

    action check_flowcache(){
        // increase flowcount, and then check its value whether
        // surpass the threshold or not.
        bit<32> flowcache_id;
        bit<32> flowcount_val;

        hash(flowcache_id,
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                standard_metadata.ingress_port,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                metadata.l4_srcPort,
                metadata.l4_dstPort,
                hdr.ipv4.dscp
            },
            (bit<32>)CACHE_SLOT
        );

        // Read from flowcount 
        FlowCount.read(flowcount_val, flowcache_id);

        // if the value is surpass threshold, then trigger digest (pack into flowcache)
        
    }

    action pack_into_flowcache(){
        // Fetch the essential element 
        // , and then pack into digest message list
        // , wait for switch agent sent them to controller
        digest<flowCache_t>((bit<32>) 1024,
            { 
                hdr.ethernet.srcAddr,
                hdr.ethernet.dstAddr,
                hdr.ethernet.etherType,
                
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                
                (bit<16>)standard_metadata.ingress_port
            });
    }

    apply {
        // if sampling find interval larger than delta time threshold,
        // then trigger digest
        if(metadata.pass_sampling == 8w1){
            if(hdr.ipv4.isValid() && hdr.tcp.isValid() || hdr.ipv4.isValid() && hdr.udp.isValid() ){
                check_flowcache();
                pack_into_flowcache();
            }
        }
    }

}

#endif