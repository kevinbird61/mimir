#include "hamming.h"

// For 32-bit
const uint32_t m1= 0x55555555;  // binary: 01 01 ...
const uint32_t m2= 0x33333333;  // binary: 0011 0011 ...
const uint32_t m4= 0x0f0f0f0f;  // binary: 11110000, 11110000 ...
const uint32_t m8= 0x00ff00ff;  // binary: 0000000011111111 (8 zeros, 8 ones)
const uint32_t m16=0x0000ffff;  // binary: 16 zeros, 16 ones
const uint32_t h01=0x01010101;  // the sum of 256 to the power of 0,1,2,3 ...

uint32_t popcount32_native(uint32_t x)
{
    x = (x&m1)+((x>>1)&m1);
    x = (x&m2)+((x>>2)&m2);
    x = (x&m4)+((x>>4)&m4);
    x = (x&m8)+((x>>8)&m8);
    x = (x&m16)+((x>>16)&m16);
    return x;
}

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

uint32_t popcount32_fast_mul(uint32_t x)
{
    x -= (x>>1) & m1;
    x = (x&m2)+((x>>2)&m2);
    x = (x+(x>>4)) & m4;
    return (x * h01) >> 24;
}

uint32_t popcount32_better(uint32_t x)
{
    uint32_t count;
    for(count=0; x; count++)
        x &= x - 1;
    return count;
}