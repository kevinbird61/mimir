#include "stdio.h"
#include "stdint.h"

/* djb2 */
unsigned long djb2(unsigned char *str){
    unsigned long hash = 5381;
    int c;

    while(c=*str++){
        hash = ((hash << 5)+hash) + c;
    }

    return hash;
}

unsigned long djb2_32(uint32_t num){
    unsigned long hash = 5381;
    hash = ((hash << 5)+hash) + num;
    return hash;
}

/* jenkins */
unsigned int jenkins(unsigned char *str){
    unsigned int hash = 0;
    while(*str){
        hash += *str;
        hash += (hash << 10);
        hash ^= (hash >> 6);
        str++;
    }

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

unsigned int jenkins_32(uint32_t num){
    unsigned int hash = 0;

    hash += num;
    hash += (hash << 10);
    hash ^= (hash >> 6);

    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

/* sdbm */
unsigned long sdbm(unsigned char *str){
    unsigned long hash = 0;
    int c;
    while (c = *str++)
        hash = c + (hash << 6) + (hash << 16) - hash;
    return hash;
}

/* lose lose */
unsigned long loselose(unsigned char *str){
    unsigned int hash = 0;
    int c;

    while (c = *str++)
	    hash += c;

	return hash;
}

int main(void){
    printf("djb2: %lu\n", djb2("a"));
    printf("djb2_32: %lu\n", djb2_32(97));
    printf("=============================\n");
    printf("jenkins: %u\n", jenkins("a"));
    printf("jenkins_32: %u\n", jenkins_32(97));
    printf("=============================\n");
    return 0;
}