#ifndef __FLOWLET__
#define __FLOWLET__

#include "headers.p4"

#define TABLE_SLOT 128

/* 
Report the message by flowlet method, 
only report the packet which trigger
our requirement: 
 - temporal
 - spatial 
*/
control flowlet(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata 
){
    // decide which method we use 
    // 0 - temporal (default)
    // 1 - spatial 
    register<bit<32>>(1) flowlet_method;

    // threshold, which are configured by controller
    register<bit<32>>(1) counter_threshold;
    register<bit<48>>(1) deltatime_threshold;

    // Maintain our KV table
    // flow id : counter value / timestamp
    register<bit<32>>(TABLE_SLOT) flowCount;
    register<bit<48>>(TABLE_SLOT) lastSeen;

    // Get flow id via hashing algorithm
    action get_flow_id(){
        hash(metadata.flow_id,
            HashAlgorithm.crc16,
            (bit<32>)0,
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                metadata.l4_srcPort,
                metadata.l4_dstPort
            },
            (bit<32>)TABLE_SLOT);
    }

    // If delta time between two packets with same flow id
    //  was surpass the time threshold, then we need to report
    //  this packet to our controller.
    action temporal(){
        bit<48> delta_t;

        // Read from the lastSeen table, and the time threshold value
        lastSeen.read(metadata.lastseen_val, metadata.flow_id);
        deltatime_threshold.read(delta_t, 0);

        // Compare the current delta time with threshold
        metadata.lastseen_val = standard_metadata.ingress_global_timestamp - metadata.lastseen_val;
        // If the delta surpass the threshold, set the flag to 1
        // ; if not, then set to 0
        metadata.send_to_cpu = (metadata.lastseen_val > delta_t ? 8w1 : 8w0);

        // Update lastSeen table
        lastSeen.write(metadata.flow_id, standard_metadata.ingress_global_timestamp);
    }

    // If delta packet counts between two packets with same flow id
    //  was surpass the time threshold, then we need to report
    //  this packet to our controller.
    action spatial(){
        bit<32> c_threshold;
        // Read from flowCount table
        flowCount.read(metadata.flowcount_val, metadata.flow_id);
        counter_threshold.read(c_threshold, 0);

        // Compare to counter threshold to find whether it surpass or not
        metadata.send_to_cpu = (metadata.flowcount_val+1 > c_threshold ? 8w1 : 8w0);
        metadata.flowcount_val = (metadata.send_to_cpu==8w1 ? 0 : metadata.flowcount_val+1);

        // Write back into flowCount table
        flowCount.write(metadata.flow_id, metadata.flowcount_val);
    }

    apply {
        // read the flag
        bit<32> flag;
        flowlet_method.read(flag, 0);

        // get flow id
        get_flow_id();

        if(flag == 32w1){
            // spatial
            spatial();
        }
        if(flag == 32w0){
            // temporal
            temporal();
        }
    }
}


#endif