#include "stdio.h"
#include "stdint.h"

/* Refs: https://en.wikipedia.org/wiki/Hamming_weight */

const uint32_t m1= 0x55555555;  // binary: 01 01 ...
const uint32_t m2= 0x33333333;  // binary: 0011 0011 ...
const uint32_t m4= 0x0f0f0f0f;  // binary: 11110000, 11110000 ...
const uint32_t m8= 0x00ff00ff;  // binary: 0000000011111111 (8 zeros, 8 ones)
const uint32_t m16=0x0000ffff;  // binary: 16 zeros, 16 ones
const uint32_t h01=0x01010101;  // the sum of 256 to the power of 0,1,2,3 ...

// native implementation 
// - 24 arithmetic operations
uint32_t popcount32_native(uint32_t x)
{
    x = (x&m1)+((x>>1)&m1);
    x = (x&m2)+((x>>2)&m2);
    x = (x&m4)+((x>>4)&m4);
    x = (x&m8)+((x>>8)&m8);
    x = (x&m16)+((x>>16)&m16);
    return x;
}

// using fewer arithmetic operations, with slow multiplication
// - 17 arithmetic operations
uint32_t popcount32_slow_mul(uint32_t x)
{
    x -= (x>>1)&m1;
    x = (x&m2)+((x>>2)&m2);
    x = (x+(x>>4)) & m4;
    x += x >> 8;
    x += x >> 16;
    // x += x >> 32;
    return (x & 0x7f);
}

// using fewer arithmetic operations, with fast multiplication
// - 12 arithmetic operation, one of which is a multiply
uint32_t popcount32_fast_mul(uint32_t x)
{
    x -= (x>>1) & m1;
    x = (x&m2)+((x>>2)&m2);
    x = (x+(x>>4)) & m4;
    return (x * h01) >> 24;
}

// better when most bits in x are 0
// - 3 arithmetic operations and 1 comparison/branch per 1 "bit" in x
uint32_t popcount32_better(uint32_t x)
{
    uint32_t count;
    for(count=0; x; count++)
        x &= x - 1;
    return count;
}

int main(void)
{
    uint32_t in1= 201, in2=348, in3=13899, in4=45832, in5=65535; // 128+64+8+1 = 11001001
    // using native implementation
    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in1, popcount32_better(in1));
    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in2, popcount32_better(in2));
    printf("Hamming Distance: %u\n", popcount32_better(in1 ^ in2));
    //printf("Union & Intersection: %u\n", (in1|in2)-2*(in1&in2));
    //printf("Hamming D / Union & Intersection: %f\n", (in1 ^ in2)/(float)((in1|in2)-2*(in1&in2)));
    printf("==================================================\n");

    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in3, popcount32_better(in3));
    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in4, popcount32_better(in4));
    printf("Hamming Distance: %u\n", popcount32_better(in3 ^ in4));
    //printf("Union & Intersection: %u\n", (in3|in4)-2*(in3&in4));
    //printf("Hamming D / Union & Intersection: %f\n", (in3 ^ in4)/(float)((in3|in4)-2*(in3&in4)));
    printf("==================================================\n");

    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in1, popcount32_better(in1));
    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in4, popcount32_better(in4));
    printf("Hamming Distance: %u\n", popcount32_better(in1 ^ in4));
    //printf("Union & Intersection: %u\n", (in1|in4)-2*(in1&in4));
    //printf("Hamming D / Union & Intersection: %f\n", (in1 ^ in4)/(float)((in1|in4)-2*(in1&in4)));
    printf("==================================================\n");

    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in1, popcount32_better(in1));
    printf("[32bits] Origin Value: %u -> Hamming Weight: %u\n", in5, popcount32_better(in5));
    printf("Hamming Distance: %u\n", popcount32_better(in1 ^ in5));
    //printf("Union & Intersection: %u\n", (in1|in5)-2*(in1&in5));
    //printf("Hamming D / Union & Intersection: %f\n", (in1 ^ in5)/(float)((in1|in5)-2*(in1&in5)));
    printf("==================================================\n");

    return 0;
}