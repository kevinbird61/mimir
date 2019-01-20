#ifndef __PORTSCAN__
#define __PORTSCAN__

#define TABLE_SLOT 512 // Cause edge switch don't have so many ID pair (so we can minimize the slot)

// Volume-based portscan detection method
control portscan_v(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // volume-based table:
    // - PortDist, value = hash(srcPort, dstPort)
    // - DiffCnt, value = counter number of mismatch in PortDist table
    // with key = hash(srcIP, dstIP)
    register<bit<32>>(TABLE_SLOT) PortDist; 
    register<bit<32>>(TABLE_SLOT) DiffCnt;

    // threshold
    register<bit<32>>(1)    CntThres;           // X.
    register<bit<32>>(1)    CntThresPow;        // X^2.
    // Report Count
    register<bit<32>>(1)    ReportCnt;

    action update_OD_pair_id(){
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
            update_OD_pair_id();
            @atomic{
                // Get the values from volume-based table
                bit<32> pre_portstatus;
                bit<32> pre_diffcnt;
                PortDist.read(pre_portstatus, metadata.flow_id);
                DiffCnt.read(pre_diffcnt, metadata.flow_id);
                
                // FIXME: Get union of portstatus & port_id 
                // - currently only use "different" to make the decision
                if(pre_portstatus != metadata.port_id){
                    pre_diffcnt = pre_diffcnt + 1;
                }

                // Check the counter value 
                bit<32> c_thres;
                CntThres.read(c_thres, 0);
                c_thres = (c_thres == 0) ? pre_diffcnt : (c_thres + pre_diffcnt)>>1;

                /*
                bit<32> c_thres_pow;
                CntThresPow.read(c_thres_pow, 0);
                c_thres_pow = (c_thres_pow == 0) ? pre_diffcnt*pre_diffcnt : (c_thres_pow + pre_diffcnt*pre_diffcnt)>>1;
                */

                CntThres.write(0, c_thres);
                // CntThresPow.write(0, c_thres_pow);

                if(pre_diffcnt > c_thres){
                    // if surpass the threshold, then report_flag=1 
                    // metadata.report_flag = 1w1;
                    metadata.send_to_cpu=1w1;
                    // bit<32> rcnt;
                    // ReportCnt.read(rcnt, 0);
                    // ReportCnt.write(0, rcnt+1);
                    // FIXME: currently drop the packet 
                    // mark_to_drop();
                    // reset diffcnt 
                    // pre_diffcnt = 0;
                }

                DiffCnt.write(metadata.flow_id, pre_diffcnt);
                PortDist.write(metadata.flow_id, metadata.port_id); // only record the latest active one
            }
        }
    }
}

#endif