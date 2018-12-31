#ifndef __LEAKYBUCKET__
#define __LEAKYBUCKET__

// Leaking rate (For illustration / Reference only)
const bit<32> FULL_CAP = 10240000; // default full capacity
const bit<32> SLOT = 1000; // how many times to empty (without any supply)
const bit<32> LEAK_RATE = FULL_CAP / SLOT; // amount for each leaking

// Using leak bucket implementation 
// Reference: https://en.wikipedia.org/wiki/Leaky_bucket
control leaky_bucket(
    inout headers_t hdr, 
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata 
){
    // essential parameter
    register<bit<32>>(1) full_capacity; // upperbound of capacity
    register<bit<32>>(1) total_capacity; // traffic capacity (bytes)
    register<bit<32>>(1) total_slot; 
    register<bit<32>>(1) each_leak_rate; 
    register<bit<48>>(1) thres_interarr; // threshold of inter-arrival time (ns)
    register<bit<48>>(1) last_seen; // last packet's timestamp

    apply {
        @atomic{
            // read from parameter 
            bit<32> full_cap;
            bit<32> cap;
            bit<32> slot;
            bit<32> leak;
            bit<48> delta_t;
            bit<48> thres_t;
            bit<48> last_t;
            full_capacity.read(full_cap, 0);
            total_capacity.read(cap, 0);
            total_slot.read(slot, 0);
            each_leak_rate.read(leak, 0);
            thres_interarr.read(thres_t, 0);
            last_seen.read(last_t, 0);

            // check capacity
            if(cap < standard_metadata.packet_length){
                // drop 
                mark_to_drop();
            } else {
                // update capacity 
                cap = cap - standard_metadata.packet_length;
            }

            // then check inter-arrival time 
            delta_t = standard_metadata.ingress_global_timestamp - last_t;
            // if delta time surpass threshold, then add some capacity back
            if(delta_t > thres_t){
                // FIXME: the number of leak-rate
                // - need to have the same ratio of delta_t size  
                cap = cap + (leak);
                if( cap > full_cap ){
                    cap = full_cap;
                }
            }
            total_capacity.write(0, cap);
            last_seen.write(0, standard_metadata.ingress_global_timestamp);
            // TODO: checking the failure time 
            /*
            if(failure_time > threshold){
                cap = FULL_CAP >> 1; // reset the cap, but only have half of capacity
                send_to_cpu(); // send the packet information to controller via packet_in / digest
            }
            */
        }
    }
}

#endif 