#ifndef __SAMPLING__
#define __SAMPLING__

#include "headers.p4"

#define TABLE_SLOT 128

/* 
Report the message by sampling method, 
only report the packet which trigger
our requirement: 
 - temporal
 - spatial 
*/
control sampling(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    // decide which method we use 
    // 0 - temporal (default)
    // 1 - spatial 
    register<bit<32>>(1) sampling_method;

    // threshold, which are configured by controller
    register<bit<32>>(1) counter_threshold;
    register<bit<48>>(1) time_threshold;
    
    register<bit<32>>(1) counter_val;
    register<bit<48>>(1) time_val; // accumulated time, compare to time threshold
    register<bit<48>>(1) lastseen_val;

    action spatial(){
        bit<32> c_threshold;
        // Read the threshold, and the current counter
        counter_val.read(metadata.flowcount_val, 0);
        counter_threshold.read(c_threshold, 0);

        // If the counter surpass the threshold, then we 
        // set the flag to send this packet to controller
        metadata.send_to_cpu = (metadata.flowcount_val+1 > c_threshold ? 8w1 : 8w0);
        metadata.flowcount_val = (metadata.send_to_cpu == 8w1 ? 32w0 : metadata.flowcount_val+1);

        // Update flowCount table
        counter_val.write(0, metadata.flowcount_val);
    }

    action temporal(){
        bit<48> t_threshold;
        bit<48> t_accumu;
        // Read the threshold, and the accumulated time
        time_threshold.read(t_threshold, 0);
        time_val.read(t_accumu, 0);
        lastseen_val.read(metadata.lastseen_val, 0);

        // If the counter surpass the threshold, then we 
        // set the flag to send this packet to controller
        t_accumu = t_accumu + (standard_metadata.ingress_global_timestamp - metadata.lastseen_val);
        metadata.send_to_cpu = (t_accumu > t_threshold ? 8w1 : 8w0);

        t_accumu = (metadata.send_to_cpu == 8w1 ? 48w0 : t_accumu);

        // Update time-related table
        time_val.write(0, t_accumu);
        lastseen_val.write(0, standard_metadata.ingress_global_timestamp);
    }
    
    apply {
        // read the flag
        bit<32> flag;
        sampling_method.read(flag, 0);

        if(flag == 32w1){
            // spatial
            spatial();
        } else {
            // temporal 
            temporal();
        }
    }
}

#endif