#ifndef __FCT__
#define __FCT__

#include "v1model.p4"

// Count the time in egress
// process complete time
control pct(
    inout standard_metadata_t standard_metadata
){
    register<bit<48>>(1) avg_pct;

    apply {
        bit<48> tmp;
        @atomic{
            avg_pct.read(tmp, 0);
            // average of complete time
            tmp = (tmp + (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp))/2;
            avg_pct.write(0, tmp);
        }
    }
}

#endif