#ifndef __HAMMING_WEIGHT__
#define __HAMMING_WEIGHT__

#include "headers.p4"

/* 32 bits version */
const bit<32> m1= 0x55555555;  // binary: 01 01 ...
const bit<32> m2= 0x33333333;  // binary: 0011 0011 ...
const bit<32> m4= 0x0f0f0f0f;  // binary: 11110000, 11110000 ...
const bit<32> m8= 0x00ff00ff;  // binary: 0000000011111111 (8 zeros, 8 ones)
const bit<32> m16=0x0000ffff;  // binary: 16 zeros, 16 ones
const bit<32> h01=0x01010101;  // the sum of 256 to the power of 0,1,2,3 ...

control popcount32_native(
    in bit<32> x,
    out bit<32> output
){
    apply {
        output = (x&m1)+((x>>1)&m1);
        output = (output&m2)+((output>>2)&m2);
        output = (output&m4)+((output>>4)&m4);
        output = (output&m8)+((output>>8)&m8);
        output = (output&m16)+((output>>16)&m16);
    }
}

control hamming_weight(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    popcount32_native() popcount;
    
    // register (using CLI to check the value)
    register<bit<32>>(1) tester;

    apply {
        @atomic {
            bit<32> tmp;
            // apply popcount function
            popcount.apply(201, tmp);
            // it should be 4
            tester.write(0, tmp);
        }
    }
}

#endif