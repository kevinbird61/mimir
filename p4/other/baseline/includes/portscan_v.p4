#ifndef __BASELINE_PORTSCAN_V__
#define __BASELINE_PORTSCAN_V__

#define TABLE_SLOT 512 

control portscan_v(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    register<bit<32>>(TABLE_SLOT) PortDist;

    register<bit<32>>(1) TotalDiffCnt;

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
                bit<32> pre_diffcnt;
                PortDist.read(pre_portstatus, metadata.flow_id);
                TotalDiffCnt.read(pre_diffcnt, 0);

                if(pre_portstatus != metadata.port_id){
                    pre_diffcnt = pre_diffcnt+1;
                }

                // Update
                TotalDiffCnt.write(0, pre_diffcnt);
                PortDist.write(metadata.flow_id, metadata.port_id); // only record the latest active one
            }
        }
    }
}

#endif