#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "packet_def.h"

// ethernet 
#define SIZE_ETHER 14

const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const char *payload; // packet payload
u_int size_ip, size_tcp, size_udp, size_existed=0;


int main(int argc, char **argv) 
{ 
    unsigned int packet_counter=0;
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

        printf("=======================================================================\n");
        printf("MAC src Addr: %s\n", ether_ntoa((struct ether_addr*)ethernet->srcAddr));
        printf("MAC dst Addr: %s\n", ether_ntoa((struct ether_addr*)ethernet->dstAddr));
        printf("ETHER type: %d\n", ethernet->etherType);
        size_existed += SIZE_ETHER;

        // Parse IPv4
        if(ethernet->etherType == (u_short)8){
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
            size_ip = IP_HL(ipv4)*4;
            size_existed += size_ip;

            if(size_ip < 20){
                printf("Invalid IPv4 header length: %u bytes\n", size_ip);
            } else {
                printf("IPv4 src Addr: %s\n", inet_ntoa(ipv4->srcAddr));
                printf("IPv4 dst Addr: %s\n", inet_ntoa(ipv4->dstAddr));
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
                printf("TCP src Port: %d\n", tcp->sport);
                printf("TCP dst Port: %d\n", tcp->dport);
            }
        } else if(ipv4->protocol == (u_char)17){
            udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
            size_udp = 8; // 8 bytes
            size_existed += size_udp;

            printf("UDP src Port: %d\n", tcp->sport);
            printf("UDP dst Port: %d\n", tcp->dport);
        }

        printf("=======================================================================\n");

        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset

        packet_counter++;
    } 
    pcap_close(handle);


    printf("%d\n", packet_counter);
    return 0;
}