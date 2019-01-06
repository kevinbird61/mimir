#include "stdio.h"
#include "stdint.h"

/* base on the spec in github/xxhash repository - https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md */

/* xxhash algorithm - xx32 */
static const uint32_t PRIME32_1 = 2654435761U;  // 0b10011110001101110111100110110001
static const uint32_t PRIME32_2 = 2246822519U;  // 0b10000101111010111100101001110111
static const uint32_t PRIME32_3 = 3266489917U;  // 0b11000010101100101010111000111101
static const uint32_t PRIME32_4 =  668265263U;  // 0b00100111110101001110101100101111
static const uint32_t PRIME32_5 =  374761393U;  // 0b00010110010101100110011110110001

// internal accumulators
uint32_t acc1,acc2,acc3,acc4;
uint32_t acc;

uint32_t _rotl(const uint32_t val, int shift){
    if ((shift &= sizeof(val)*8 - 1) == 0)
        return val;
    return (val << shift) | (val >> (sizeof(val)*8 - shift));
}

uint32_t _rotr(const uint32_t val, int shift){
    if((shift &= sizeof(val)*8 - 1) == 0)
        return val;
    return (val >> shift) | (val << (sizeof(val)*8 - shift));
}

/*
    Notice: all process progress within the 
    assumption:
    - all input are 32-bits
*/

/* step 1: initialize internal accumulators */
void xxhash32_init(uint32_t seed){
    acc1 = seed + PRIME32_1 + PRIME32_2;
    acc2 = seed + PRIME32_2;
    acc3 = seed;
    acc4 = seed - PRIME32_1;
}

/* step 2: process stripes
    - we only have one 32-bits input, so N=1. 
    lane1 = only input

    Pseudo code:

    accN = accN + (laneN * PRIME32_2);
    accN = accN <<< 13;
    accN = accN * PRIME32_1;
*/
void xxhash32_process_stripes(uint32_t lane){
    acc1 = acc1 + (lane * PRIME32_2);
    acc1 = _rotl(acc1, 13);
    acc1 = acc1 * PRIME32_1;
}

/* step 3: accumulator convergence */
void xxhash32_conv(){
    acc = _rotl(acc1, 1) + _rotl(acc2, 7) + 
        _rotl(acc3, 12) + _rotl(acc4, 18);
}

/* step 4: add input length */
void xxhash32_add_inlen(){
    acc += 32;
}

/* step 5: consume remaining input
    - because our assumption, so this step skip.
*/

/* step 6: final mix */
void xxhash32_final(){
    acc = acc ^ (acc >> 15);
    acc = acc * PRIME32_2;
    acc = acc ^ (acc >> 13);
    acc = acc * PRIME32_3;
    acc = acc ^ (acc >> 16);
}

int main(void){
    uint32_t input = 32;
    xxhash32_init(0);
    xxhash32_process_stripes(input);
    xxhash32_conv();
    xxhash32_add_inlen();
    xxhash32_final();

    printf("%d --xxhash32--> %u\n", input, acc);
    printf("sizeof: %ld\n", sizeof(uint32_t));
    input = acc;
    xxhash32_init(0);
    xxhash32_process_stripes(input);
    xxhash32_conv();
    xxhash32_add_inlen();
    xxhash32_final();

    printf("%d --xxhash32--> %u\n", input, acc);

    return 0;
}