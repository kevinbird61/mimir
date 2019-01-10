#ifndef __TAXONOMY_UDPSCAN__
#define __TAXONOMY_UDPSCAN__

/* refs: http://www.fukuda-lab.org/mawilab/classification/index.html#Mazel2014TRAC */

#include "headers.p4"

#define TABLE_SLOT 512

control udp_network_scan(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    register<bit<32>>(1) nb_packets;
    register<bit<32>>(1) nb_src_addr;
    register<bit<32>>(1) nb_dst_addr;
    register<bit<32>>(1) nb_udp_packets;

    register<bit<32>>(TABLE_SLOT) src_addr_tbl; // maintain the existed address
    register<bit<32>>(TABLE_SLOT) dst_addr_tbl;

    action get_addr_hash(){
        hash(metadata.src_addr_id,
            HashAlgorithm.crc32,
            32w0,
            {
                hdr.ipv4.srcAddr
            },(bit<32>)TABLE_SLOT);
        
        hash(metadata.dst_addr_id,
            HashAlgorithm.crc32,
            32w0,
            {
                hdr.ipv4.dstAddr
            },(bit<32>)TABLE_SLOT);
    }

    apply {
        bit<32> pre_pkts;
        bit<32> pre_src_addr;
        bit<32> pre_dst_addr;
        bit<32> cnt_src_addr;
        bit<32> cnt_dst_addr;
        bit<32> pre_udp_pkts;

        get_addr_hash();

        @atomic {
            // inc nb_pkts
            nb_packets.read(pre_pkts, 0);
            pre_pkts = pre_pkts + 1;
            nb_packets.write(0, pre_pkts);
            if(hdr.udp.isValid()){
                nb_udp_packets.read(pre_udp_pkts, 0);
                pre_udp_pkts = pre_udp_pkts + 1;
                nb_udp_packets.write(0, pre_udp_pkts);
            }

            // find addr is existed or not
            src_addr_tbl.read(pre_src_addr, metadata.src_addr_id);
            nb_src_addr.read(cnt_src_addr, 0);
            if(pre_src_addr == 0){
                // set flag to 1
                src_addr_tbl.write(metadata.src_addr_id, 1);
                // inc nb_src_addr
                cnt_src_addr = cnt_src_addr + 1;
                nb_src_addr.write(0, cnt_src_addr);
            }

            dst_addr_tbl.read(pre_dst_addr, metadata.dst_addr_id);
            nb_dst_addr.read(cnt_dst_addr, 0);
            if(pre_dst_addr == 0){
                // set flag to 1
                dst_addr_tbl.write(metadata.dst_addr_id, 1);
                // inc nb_dst_addr
                cnt_dst_addr = cnt_dst_addr + 1;
                nb_dst_addr.write(0, cnt_dst_addr);
            }
        }
    }
}

#endif