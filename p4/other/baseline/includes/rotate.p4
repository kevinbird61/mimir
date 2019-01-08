#ifndef __ROTATE__
#define __ROTATE__

/* Provide rotate operations in P4 */

// rotate left
control rotl(
    in bit<32> val,
    in bit<8> shift,
    out bit<32> result
){
    apply {
        bit<32> check;
        check = (bit<32>)shift & 31;
        if(check != 32w0){
            result = (val << shift) | (val >> (8w32 - shift));
        } else {
            result = val;
        }
    }
}

// rotate right
control rotr(
    in bit<32> val,
    in bit<8> shift,
    out bit<32> result
){
    apply {
        bit<32> check;
        check = (bit<32>)shift & 31;
        if(check != 32w0){
            result = (val >> shift) | (val << (8w32 - shift));
        } else {
            result = val;
        }
    }
}


#endif 