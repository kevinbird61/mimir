#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "hash/xxhash.h"
#include "lib/packet_def.h"
#include "lib/hash.h"

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

typedef struct _flow {
    uint32_t srcIP;
    uint32_t dstIP;
    char used;
} flow_id;

typedef struct _port {
    u_short sport;
    u_short dport;
    char used;
} port_id;

// hash table 
flow_id flow[TABLE_SLOT]={0};
port_id tcp_port[TABLE_SLOT]={0};
port_id udp_port[TABLE_SLOT]={0};
unsigned int ip_collision=0, ipm=0, tcp_port_collision=0, udp_port_collision=0;
unsigned int flow_unuse=TABLE_SLOT, tcp_unuse=TABLE_SLOT, udp_unuse=TABLE_SLOT;

int main(int argc, char **argv) 
{ 
    unsigned int packet_counter=0,tcp_counter=0,udp_counter=0;
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
                //printf("IPv4 src Addr: %s\n", inet_ntoa(ipv4->srcAddr));
                //printf("IPv4 dst Addr: %s\n", inet_ntoa(ipv4->dstAddr));
                unsigned char IP[8]={0};
                *IP = ipv4->srcAddr.s_addr;
                *(IP+4) = ipv4->dstAddr.s_addr;
                // get flow id
                unsigned long index = XXH32(IP, 8, TABLE_SLOT) % TABLE_SLOT;
                // unsigned long index = jenkins(IP) % TABLE_SLOT;
                // unsigned int index = crc16(IP, 16) % TABLE_SLOT;
                // unsigned int index = crc32(IP) % TABLE_SLOT;
                // check 
                if(flow[index].srcIP != ipv4->srcAddr.s_addr || flow[index].dstIP != ipv4->dstAddr.s_addr){
                    ip_collision++;
                    flow[index].srcIP = ipv4->srcAddr.s_addr;
                    flow[index].dstIP = ipv4->dstAddr.s_addr;
                    if(flow[index].used==0){
                        flow_unuse--;
                        flow[index].used=1;
                    }
                } else {
                    ipm++;
                }
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
                    // get flow id
                    // unsigned long index = XXH32(Port, 4, TABLE_SLOT) % TABLE_SLOT;
                    // unsigned long index = jenkins(Port) % TABLE_SLOT;
                    unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                    // unsigned int index = crc32(Port) % TABLE_SLOT;
                    // check 
                    if(tcp_port[index].sport != tcp->sport || tcp_port[index].dport != tcp->dport){
                        tcp_port_collision++;
                        tcp_port[index].sport = tcp->sport;
                        tcp_port[index].dport = tcp->dport;
                        if(tcp_port[index].used==0){
                            tcp_unuse--;
                            tcp_port[index].used=1;
                        }
                    }
                }

                tcp_counter++;
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                size_udp = 8; // 8 bytes
                size_existed += size_udp;

                unsigned char Port[4]={0};
                *Port = udp->sport;
                *(Port+2) = udp->dport;
                // get flow id
                // unsigned long index = XXH32(Port, 4, TABLE_SLOT) % TABLE_SLOT;
                // unsigned long index = jenkins(Port) % TABLE_SLOT;
                // unsigned long index = djb2(Port) % TABLE_SLOT;
                unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                // unsigned int index = crc32(Port) % TABLE_SLOT;
                // check 
                if(udp_port[index].sport != udp->sport || udp_port[index].dport != udp->dport){
                    udp_port_collision++;
                    udp_port[index].sport = udp->sport;
                    udp_port[index].dport = udp->dport;
                    if(udp_port[index].used==0){
                        udp_unuse--;
                        udp_port[index].used=1;
                    }
                }
                udp_counter++;
            }
            packet_counter++;
        }
        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset
    } 
    pcap_close(handle);

    printf("=======================================================================\n");
    printf("IP Collision: %u, Collision rate: %f\n", ip_collision, (float)ip_collision/packet_counter);
    printf("TCP Port Collision: %u, Collision rate: %f\n", tcp_port_collision, (float)tcp_port_collision/tcp_counter);
    printf("UDP Port Collision: %u Collision rate: %f\n", udp_port_collision, (float)udp_port_collision/udp_counter);
    printf("=======================================================================\n");
    printf("Unuse flow table: %u\n", flow_unuse);
    printf("Unuse TCP Port table: %u\n", tcp_unuse);
    printf("Unuse UDP Port table: %u\n", udp_unuse);
    printf("=======================================================================\n");

    return 0;
}