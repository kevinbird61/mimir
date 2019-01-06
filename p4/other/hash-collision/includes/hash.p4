#ifndef __MYHASH__
#define __MYHASH__

/* mimic p4 hash function call:*/
/* djb2
    - per 32 bits
    call init first: djb2_32_init.apply(<input_1>, 0, TABLE_SLOT, <output>)
    then call: djb2_32.apply(<input_2), 0, TABLE_SLOT, <output>)
*/
control djb2_32_init(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash first
        result = 32w5381;
        result = ((result << 5) + result) + number;
        // then get mod by (ub-lb)
        // result = result & (ub-lb-1);
    }
}
control djb2_32(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash
        result = ((result << 5) + result) + number;
        // then get mod by (ub-lb)
        result = result & (ub-lb-1);
    }
}

/* jenkins
    - per 32 bits (same way as above)
*/
control jenkins_32_init(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash first
        result = 32w0;
        result = result + number;
        result = result + (result << 10);
        result = result ^ (result >> 6);

        //result += (hash << 3);
        //result ^= (hash >> 11);
        //result += (hash << 15);
        // then get mod by (ub-lb)
        // result = result & (ub-lb-1);
    }
}
control jenkins_32(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash (conti.)
        result = result + number;
        result = result + (result << 10);
        result = result ^ (result >> 6);

        result = result + (result << 3);
        result = result ^ (result >> 11);
        result = result + (result << 15);
        // then get mod by (ub-lb)
        result = result & (ub-lb-1);
    }
}

/* sdbm 
    - per 32 bits (same way as above)
*/
control sdbm_32_init(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash first
        result = 32w0;
        result = number + (result << 6) + (result << 16) - result;
        // then get mod by (ub-lb)
        // result = result & (ub-lb-1);
    }
}
control sdbm_32(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash
        result = number + (result << 6) + (result << 16) - result;
        // then get mod by (ub-lb)
        result = result & (ub-lb-1);
    }
}

/* lose-lose
    - per 32 bits (same way as above)
*/
control loselose_32_init(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash first
        result = 32w0;
        result = result + number + (result << 6) + (result << 16) - result;
        // then get mod by (ub-lb)
        // result = result & (ub-lb-1);
    }
}
control loselose_32(
    in bit<32> number,
    in bit<32> lb,
    in bit<32> ub,
    out bit<32> result
){
    apply {
        // hash
        result = result + number + (result << 6) + (result << 16) - result;
        // then get mod by (ub-lb)
        result = result & (ub-lb-1);
    }
}


#endif