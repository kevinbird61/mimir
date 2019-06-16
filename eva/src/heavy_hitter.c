/* find heavy hitter from pcap */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <math.h>

#include "hash/xxhash.h"
#include "../lib/packet_def.h"
#include "../lib/packet_stat.h"
#include "../lib/hash.h"

#define MIN(A,B) ((A>B)?B:A)

// hash table size 
#define TABLE_SLOT 512
// ethernet 
#define SIZE_ETHER 14

const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const char *payload; // packet payload
u_int size_ip, size_tcp, size_udp, size_existed=0;

typedef struct _sketch {
    struct in_addr srcAddr;
    struct in_addr dstAddr;
    uint32_t cnt;               // counter value
} sketch_t;

// h*t 
// h = number of distinct hash function.
// t = table size 
sketch_t hh[3][TABLE_SLOT]={0};

// report ip (non-sketch)
map_int_t ipv4_src_addr;
map_int_t ipv4_dst_addr;
// report ip (sketch)
map_int_t ipv4_src_addr_s;
map_int_t ipv4_dst_addr_s;

int main(int argc, char **argv)
{
    char *pcapfile;
    int ch, fflag=0;
    while((ch = getopt(argc,argv,"f:"))!=-1){
        // printf("optind: %d\n", optind);
        switch(ch){
            case 'f':
                // filename = optarg
                fflag=1;
                printf("Input PCAP filename: %s\n", optarg);
                pcapfile=optarg;
                break;
            default:
                break;
        }
    }

    if(!fflag){
        fprintf(stderr, "Using -f <pcapfile> to specify input pcap file.\n"); 
        exit(1); 
    }
    struct pcap_pkthdr header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];  
    handle = pcap_open_offline(pcapfile, errbuf); 
    if (handle == NULL) { 
        fprintf(stderr, "Couldn't open pcap file: %s\n", pcapfile); 
        fprintf(stderr, "%s\n", errbuf);
        return(2); 
    } 
    // variables 
    uint32_t flow_id;
    // eva 
    map_init(&ipv4_src_addr);
    map_init(&ipv4_dst_addr);

    // Get each packet from pcap file
    while (packet = pcap_next(handle,&header)) {
        // printf("%d\n", header.len);
        /* Packet parsing process */
        ethernet = (struct sniff_ethernet*)(packet);
        size_existed += SIZE_ETHER;

        // Parse IPv4
        if(ethernet->etherType == (u_short)8){
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
            size_ip = IP_HL(ipv4)*4;
            size_existed += size_ip;
            if(size_ip < 20){
                printf("Invalid IPv4 header length: %u bytes\n", size_ip);
            } else {
                // IPv4 
                unsigned char IP[8]={0};
                *IP = ipv4->srcAddr.s_addr;
                *(IP+4) = ipv4->dstAddr.s_addr;
                unsigned int index, min=~0;
                // - First hash function
                index = crc16(IP, 8)%TABLE_SLOT;
                hh[0][index].cnt++;
                hh[0][index].srcAddr = ipv4->srcAddr;
                hh[0][index].dstAddr = ipv4->dstAddr;
                min = MIN(hh[0][index].cnt, min);
                map_set(&ipv4_src_addr, inet_ntoa(ipv4->srcAddr), min);
                map_set(&ipv4_dst_addr, inet_ntoa(ipv4->dstAddr), min);
                // - Second hash function
                index = (unsigned int)XXH32(IP, 8, TABLE_SLOT)%TABLE_SLOT;
                hh[1][index].cnt++;
                hh[1][index].srcAddr = ipv4->srcAddr;
                hh[1][index].dstAddr = ipv4->dstAddr;
                min = MIN(hh[1][index].cnt, min);
                // - Third hash function
                index = crc32(IP)%TABLE_SLOT;
                hh[2][index].cnt++;
                hh[2][index].srcAddr = ipv4->srcAddr;
                hh[2][index].dstAddr = ipv4->dstAddr;
                min = MIN(hh[2][index].cnt, min);
                // Write 
                map_set(&ipv4_src_addr_s, inet_ntoa(ipv4->srcAddr), min);
                map_set(&ipv4_dst_addr_s, inet_ntoa(ipv4->dstAddr), min);
            }

            // Parse TCP 
            /*if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;

                if(size_tcp < 20){
                    printf("Invalid TCP header length: %u bytes\n", size_tcp);
                } else {

                }
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                size_udp = 8; // 8 bytes
                size_existed += size_udp;
            }*/
        }
        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset
    }
    pcap_close(handle);

    // check hh table 
    const char *key;
    uint32_t reportCntAvg=0, Cnt=0, ReportNum=0;
    float reportCntVar=0.0;
    printf("=============================================================\n");
    printf("Non-Sketch version\n");
    printf("=============================================================\n");
    map_iter_t iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of report counter (diffcnt): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of report counter (diffcnt): %f\n", sqrt(reportCntVar/Cnt));
    // find hh 
    iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        if(reportCnt > (reportCntAvg/Cnt + 3*sqrt(reportCntVar/Cnt))){
            //printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports: %d\n", ReportNum);
    printf("=============================================================\n");

    reportCntAvg=0;
    Cnt=0;
    ReportNum=0;
    reportCntVar=0.0;
    printf("=============================================================\n");
    printf("Sketch version\n");
    printf("=============================================================\n");
    iter = map_iter(&ipv4_src_addr_s);
    while ((key = map_next(&ipv4_src_addr_s, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_s, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of report counter (diffcnt): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr_s);
    while ((key = map_next(&ipv4_src_addr_s, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_s, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of report counter (diffcnt): %f\n", sqrt(reportCntVar/Cnt));
    // find hh 
    iter = map_iter(&ipv4_src_addr_s);
    while ((key = map_next(&ipv4_src_addr_s, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_s, key);
        if(reportCnt > (reportCntAvg/Cnt + 3*sqrt(reportCntVar/Cnt))){
            //printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports: %d\n", ReportNum);
    printf("=============================================================\n");

    return 0;
}