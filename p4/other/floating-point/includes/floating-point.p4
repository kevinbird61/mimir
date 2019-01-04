#ifndef __FLOAT__
#define __FLOAT__

#include "headers.p4"
#include "log.p4"

// add floating point operator 
control add_f(
    in bit<1> in1_sign,
    in bit<8> in1_expon,
    in bit<23>  in1_mantissa,
    in bit<1> in2_sign,
    in bit<8> in2_expon,
    in bit<23>  in2_mantissa,
    out bit<1>  sign,
    out bit<8>  expon,
    out bit<23> mantissa
){
    apply {
        // Check sign 
        if(in1_sign == in2_sign){
            // normalize 
            bit<8> shift_bits;
            if(in1_expon > in2_expon){
                // Difference (use to shift mantissa)
                shift_bits = in1_expon-in2_expon;
                /* 
                    Shifting the mantissa 
                    - TODO: handle the add carry
                */
                mantissa = in1_mantissa + (in2_mantissa >> shift_bits);
                // Exponent 
                expon = in1_expon;
                // Sign 
                sign = in1_sign;
            } else {
                // in1_expon <= in2_expon
                // Difference (use to shift mantissa)
                shift_bits = in2_expon-in1_expon;
                /* 
                    Shifting the mantissa 
                    - TODO: handle the add carry
                */
                mantissa = in2_mantissa + (in1_mantissa >> shift_bits);
                // Exponent 
                expon = in2_expon;
                // Sign 
                sign = in1_sign;
            }
        } else {
            // TODO
            sign=in1_sign;
            expon=in1_expon;
            mantissa=in1_mantissa;
        }
    }
}

control floating_point(
    inout headers_t hdr,
    inout metadata_t metadata,
    inout standard_metadata_t standard_metadata
){
    add_f() add_op;

    // register (using CLI to check the value)
    register<bit<1>>(1) r_sign;
    register<bit<8>>(1) r_expon;
    register<bit<23>>(1) r_mantissa;

    apply {
        @atomic{
            bit<1> sign;
            bit<8> expon;
            bit<23> mantissa;
            // call add 
            add_op.apply(
                1w0, 8w129, 23w6291456,
                1w0, 8w130, 23w6291456,
                sign, expon, mantissa
            );
            // write
            r_sign.write(0, sign);
            r_expon.write(0, expon);
            r_mantissa.write(0, mantissa);
        }
    }
}

#endif