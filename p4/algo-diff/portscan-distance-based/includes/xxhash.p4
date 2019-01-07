#ifndef __XXHASH__
#define __XXHASH__

#include "rotate.p4"

const bit<32> PRIME32_1 = 2654435761;
const bit<32> PRIME32_2 = 2246822519;
const bit<32> PRIME32_3 = 3266489917;
const bit<32> PRIME32_4 =  668265263;
const bit<32> PRIME32_5 =  374761393;

control xxhash32_init(
    in bit<32> number,
    in bit<32> seed,
    out bit<32> acc
){
    rotl() rl;
    rotr() rr;

    apply {
        bit<32> acc1;
        bit<32> acc2;
        bit<32> acc3;
        bit<32> acc4;

        // step 1
        acc1 = seed + PRIME32_1 + PRIME32_2;
        acc2 = seed + PRIME32_2;
        acc3 = seed;
        acc4 = seed - PRIME32_1;
        acc = 0;

        // step 2
        acc1 = acc1 + (number * PRIME32_2);
        rl.apply(acc1, 13, acc1);
        acc1 = acc1 * PRIME32_1;

        // step 3
        bit<32> tmp;
        rl.apply(acc1, 1, tmp);
        acc = acc + tmp;
        rl.apply(acc2, 7, tmp);
        acc = acc + tmp;
        rl.apply(acc3, 12, tmp);
        acc = acc + tmp;
        rl.apply(acc4, 18, tmp);
        acc = acc + tmp;

        // step 4
        acc = acc + 32;

        // step 5 (skip)

        // step 6
        //acc = acc ^ (acc >> 15);
        //acc = acc * PRIME32_2;
        //acc = acc ^ (acc >> 13);
        //acc = acc * PRIME32_3;
        //acc = acc ^ (acc >> 16);

        // assign 
        // reuslt = acc;

        // then get mod by (ub-lb)
        //result = result & (ub-lb-1);
    }
}

control xxhash32(
    in bit<32> number,
    in bit<32> acc,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    rotl() rl;
    rotr() rr;

    apply {
        // step 5 (remaining input)
        /* FIXME: currently only support one remaining input */
        result = acc + number * PRIME32_5;
        bit<32> tmp;
        rl.apply(acc, 11, tmp);
        result = tmp * PRIME32_1;
        // step 6
        result = result ^ (result >> 15);
        result = result * PRIME32_2;
        result = result ^ (result >> 13);
        result = result * PRIME32_3;
        result = result ^ (result >> 16);

        // then get mod by (ub-lb)
        result = result & (ub-lb-1);
    }
}


#endif