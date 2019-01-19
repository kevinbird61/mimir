#ifndef __HAMMING__
#define __HAMMING__

#include "stdio.h"
#include "stdint.h"

/* Refs: https://en.wikipedia.org/wiki/Hamming_weight */

// different method to calculate hamming weight

// native implementation 
// - 24 arithmetic operations
uint32_t popcount32_native(uint32_t x);

// using fewer arithmetic operations, with slow multiplication
// - 17 arithmetic operations
uint32_t popcount32_slow_mul(uint32_t x);

// using fewer arithmetic operations, with fast multiplication
// - 12 arithmetic operation, one of which is a multiply
uint32_t popcount32_fast_mul(uint32_t x);

// better when most bits in x are 0
// - 3 arithmetic operations and 1 comparison/branch per 1 "bit" in x
uint32_t popcount32_better(uint32_t x);

#endif