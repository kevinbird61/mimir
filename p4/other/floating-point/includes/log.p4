#ifndef __LOG__
#define __LOG__

#include "headers.p4"

// X = log2(2^X+e)
// input: 2^X+e, note as N
// output: X
control log2(
    in bit<32> N,
    out bit<32> X
){
    apply{
        bit<32> n;
        bit<32> s;
        bit<32> t;
        n = N;
        
        t = ((n > 0xffff)? 32w1 : 32w0) << 4; 
        n = n >> t;
        
        s = ((n > 0xff)? 32w1 : 32w0) << 3;
        n = n >> s;
        t = t | s;

        s = ((n > 0xf)? 32w1 : 32w0) << 2;
        n = n >> s;
        t = t | s;

        s = ((n > 0x3)? 32w1 : 32w0) << 1;
        n = n >> s;
        t = t | s;

        X = t | (n >> 1);
    }
}

control log_exp(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata 
){
    log2() lg2;

    // register (using CLI to check the value)
    register<bit<32>>(1) tester;

    apply {
        @atomic{
            bit<32> tmp;
            // assign 128 = 2^7
            lg2.apply(128, tmp);
            // the value should be 7
            tester.write(0, tmp);
        }
    }
}

#endif