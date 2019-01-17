#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "lib/packet_def.h"
#include "lib/hash.h"

#include "hash/xxhash.h"
#include "cmap/map.h"

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

// data structure of evaluation
typedef struct _eva {
    uint32_t port_id;
    uint32_t diffcnt;   // number of difference
    uint32_t hamming;   // hamming distance
} eva_t;

// report ip 
map_int_t ipv4_src_addr;
map_int_t ipv4_dst_addr;

// Key-Value pair 
eva_t tcp_tb[TABLE_SLOT]={0};
eva_t udp_tb[TABLE_SLOT]={0};

// map inc 
void map_inc(map_int_t *m, void *key){
    int *ori = map_get(m, key);
    if(ori){
        map_set(m, key, (*ori)+1 );
    } else {
        map_set(m, key, 1);
    }
}


int main(int argc, char **argv) 
{ 
    unsigned int flow_id;
    struct pcap_pkthdr header; 
    const u_char *packet;
    if (argc < 2) { 
        fprintf(stderr, "Usage: %s <pcap>\n", argv[0]); 
        exit(1); 
    } 
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];  
    handle = pcap_open_offline(argv[1], errbuf); 
    if (handle == NULL) { 
        fprintf(stderr, "Couldn't open pcap file: %s\n", argv[1]); 
        fprintf(stderr, "%s\n", errbuf);
        return(2); 
    } 

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
                unsigned char IP[8]={0};
                *IP = ipv4->srcAddr.s_addr;
                *(IP+4) = ipv4->dstAddr.s_addr;
                // get flow id
                flow_id = crc16(IP, 8) % TABLE_SLOT;
            }
            // Parse TCP 
            if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;

                if(size_tcp < 20){
                    printf("Invalid TCP header length: %u bytes\n", size_tcp);
                } else {
                    unsigned char Port[4]={0};
                    *Port = tcp->sport;
                    *(Port+2) = tcp->dport;
                    // get port id
                    unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                    // cal 
                    if(tcp_tb[flow_id].port_id != index){
                        tcp_tb[flow_id].port_id = index; // update
                        tcp_tb[flow_id].diffcnt++;
                        // report
                        if(tcp_tb[flow_id].diffcnt > 30){
                            //printf("ipv4 src addr: %s\n", inet_ntoa(ipv4->srcAddr));
                            //printf("ipv4 dst addr: %s\n", inet_ntoa(ipv4->dstAddr));
                            map_inc(&ipv4_src_addr, inet_ntoa(ipv4->srcAddr));
                            map_inc(&ipv4_dst_addr, inet_ntoa(ipv4->dstAddr));
                        }
                    }
                }
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                size_udp = 8; // 8 bytes
                size_existed += size_udp;

                unsigned char Port[4]={0};
                *Port = udp->sport;
                *(Port+2) = udp->dport;
                // get port id
                unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                // cal 
                if(udp_tb[flow_id].port_id != index){
                    udp_tb[flow_id].port_id = index; // update
                    udp_tb[flow_id].diffcnt++;
                    // report
                    if(udp_tb[flow_id].diffcnt > 20){
                        //printf("ipv4 src addr: %s\n", inet_ntoa(ipv4->srcAddr));
                        //printf("ipv4 dst addr: %s\n", inet_ntoa(ipv4->dstAddr));
                        map_inc(&ipv4_src_addr, inet_ntoa(ipv4->srcAddr));
                        map_inc(&ipv4_dst_addr, inet_ntoa(ipv4->dstAddr));
                    }
                }
            }
        }
        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset
    } 
    pcap_close(handle);

    uint32_t tdiff=0, udiff=0;
    for(int i=0;i<TABLE_SLOT;i++){
        tdiff += tcp_tb[i].diffcnt;
        udiff += udp_tb[i].diffcnt;
    }

    printf("Avg TCP diff. count: %.2f\n", (float)tdiff/TABLE_SLOT);
    printf("Avg UDP diff. count: %.2f\n", (float)udiff/TABLE_SLOT);

    const char *key;
    uint32_t reportCntAvg=0, Cnt=0;
    map_iter_t iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        // reportCntAvg += reportCnt;
        // Cnt++;
        if(*map_get(&ipv4_src_addr, key) > 500){
            printf("%s -> %d\n",  key , reportCnt);
        }
    }
    // printf("Avg Report Counter: %f\n", reportCntAvg/(float)Cnt);
    /*iter = map_iter(&ipv4_dst_addr);
    while ((key = map_next(&ipv4_dst_addr, &iter))) {
        printf("%s -> %d\n",  key , *map_get(&ipv4_dst_addr, key));
    }*/

    return 0;
}