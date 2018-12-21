#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>

#include "packet_def.h"
#include "packet_stat.h"

// ethernet 
#define SIZE_ETHER 14

const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const char *payload; // packet payload
u_int size_ip, size_tcp, size_udp, size_existed=0;

// for evaluation
struct packet_stat* eva;
FILE *fIP, *fproto, *ftcpPort, *fudpPort;

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

    // init eva
    eva = pktStat_init();

    // Get each packet from pcap file
    while (packet = pcap_next(handle,&header)) {
        // printf("%d\n", header.len);

        /* Packet parsing process */
        ethernet = (struct sniff_ethernet*)(packet);

        // printf("=======================================================================\n");
        //printf("MAC src Addr: %s\n", ether_ntoa((struct ether_addr*)ethernet->srcAddr));
        //printf("MAC dst Addr: %s\n", ether_ntoa((struct ether_addr*)ethernet->dstAddr));
        //printf("ETHER type: %d\n", ethernet->etherType);
        size_existed += SIZE_ETHER;

        // count ethernet address statistic
        pktStat_inc(&eva->eth_addr_stat, (void *)ethernet->srcAddr);
        pktStat_inc(&eva->eth_addr_stat, (void *)ethernet->dstAddr);
        char et[2]; /* adapt for integer */
        sprintf(et, "%d", ethernet->etherType);
        pktStat_inc(&eva->eth_type_stat, (void *) et);

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

                // count IPv4 address statistic
                pktStat_inc(&eva->ipv4_addr_stat, inet_ntoa(ipv4->srcAddr));
                pktStat_inc(&eva->ipv4_addr_stat, inet_ntoa(ipv4->dstAddr));
                char pt[2];
                sprintf(pt, "%d", ipv4->protocol);
                pktStat_inc(&eva->ipv4_proto_stat, pt);
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
                // printf("TCP src Port: %d\n", tcp->sport);
                // printf("TCP dst Port: %d\n", tcp->dport);
                char port[2];
                sprintf(port, "%d", tcp->sport);
                pktStat_inc(&eva->tcp_port_stat, port);
                sprintf(port, "%d", tcp->dport);
                pktStat_inc(&eva->tcp_port_stat, port);
            }
        } else if(ipv4->protocol == (u_char)17){
            udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
            size_udp = 8; // 8 bytes
            size_existed += size_udp;

            // printf("UDP src Port: %d\n", tcp->sport);
            // printf("UDP dst Port: %d\n", tcp->dport);
            char port[2];
            sprintf(port, "%d", udp->sport);
            pktStat_inc(&eva->udp_port_stat, port);
            sprintf(port, "%d", udp->dport);
            pktStat_inc(&eva->udp_port_stat, port);
        }
        // printf("=======================================================================\n");

        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset

        packet_counter++;
    } 
    pcap_close(handle);

    fIP = fopen("output/ip_raw.txt", "w+");
    fproto = fopen("output/proto_raw.txt", "w+");
    ftcpPort = fopen("output/tcp_raw.txt", "w+");
    fudpPort = fopen("output/udp_raw.txt", "w+");

    /* Check eva result */
    printf("=======================================================================\n");
    const char *key;
    map_iter_t iter = map_iter(&eva->eth_addr_stat);
    printf("MAC Address Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->eth_addr_stat, &iter))) {
        printf("%s -> %d\n",  ether_ntoa((struct ether_addr*)key), *map_get(&eva->eth_addr_stat, key));
    }
    iter = map_iter(&eva->eth_type_stat);
    printf("=======================================================================\n");
    printf("EtherType Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->eth_type_stat, &iter))) {
        printf("%s -> %d\n", key, *map_get(&eva->eth_type_stat, key));
    }
    iter = map_iter(&eva->ipv4_addr_stat);
    printf("=======================================================================\n");
    printf("IP Address Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->ipv4_addr_stat, &iter))) {
        printf("%s -> %d\n", key, *map_get(&eva->ipv4_addr_stat, key));
        fprintf(fIP, "%s %d\n", key, *map_get(&eva->ipv4_addr_stat, key));
    }
    iter = map_iter(&eva->ipv4_proto_stat);
    printf("=======================================================================\n");
    printf("IP Protocol Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->ipv4_proto_stat, &iter))) {
        printf("%s -> %d\n", key, *map_get(&eva->ipv4_proto_stat, key));
        fprintf(fproto, "%s %d\n", key, *map_get(&eva->ipv4_proto_stat, key));
    }
    iter = map_iter(&eva->tcp_port_stat);
    printf("=======================================================================\n");
    printf("TCP Port Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->tcp_port_stat, &iter))) {
        printf("%s -> %d\n", key, *map_get(&eva->tcp_port_stat, key));
        fprintf(ftcpPort, "%s %d\n", key, *map_get(&eva->tcp_port_stat, key));
    }
    iter = map_iter(&eva->udp_port_stat);
    printf("=======================================================================\n");
    printf("UDP Port Stat: \n");
    printf("=======================================================================\n");
    while ((key = map_next(&eva->udp_port_stat, &iter))) {
        printf("%s -> %d\n", key, *map_get(&eva->udp_port_stat, key));
        fprintf(fudpPort, "%s %d\n", key, *map_get(&eva->udp_port_stat, key));
    }

    printf("=======================================================================\n");

    printf("Number of packets: %d\n", packet_counter);
    return 0;
}