#include "stdio.h"

unsigned int ulog2 (unsigned int u)
{
    unsigned int s, t;

    t = (u > 0xffff) << 4; u >>= t;
    s = (u > 0xff  ) << 3; u >>= s, t |= s;
    s = (u > 0xf   ) << 2; u >>= s, t |= s;
    s = (u > 0x3   ) << 1; u >>= s, t |= s;

    return (t | (u >> 1));
}

int main(int argc, char *argv[]){
    unsigned int test=6784;

    printf("%u\n", ulog2(test));

    return 0;
}