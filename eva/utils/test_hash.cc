#include <iostream>

#include "hash/xxhash.h"
#include "hash.h"

using namespace std;

int main(void){
    unsigned char IP_r[8]={'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'};
    unsigned char IP[8]={'e', 'f', 'g', 'h', 'a', 'b', 'c', 'd'};

    unsigned long index = XXH32(IP, 8, 512)%512;
    cout << "Front: " << index << endl;

    // reverse 
    index = XXH32(IP_r, 8, 512)%512;
    cout << "Reverse: " << index << endl;
}