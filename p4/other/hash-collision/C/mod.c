#include <stdio.h>

int main(void){
    // by % operator
    printf("%d mod %d = %d\n", 135, 32, 135%32);
    // by bitwise operator 
    // n % 2^x = n & (2^x - 1)
    printf("%d mod %d = %d\n", 135, 32, 135 & (32-1));
    return 0;
}