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
int unique_hosts=0, uniq_src_ip=0, uniq_dst_ip=0, uniq_tcp=0, uniq_tcp_src=0, uniq_tcp_dst=0, uniq_udp=0, uniq_udp_src=0, uniq_udp_dst=0;

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
                // count for src/dst
                pktStat_inc(&eva->ipv4_src_addr, inet_ntoa(ipv4->srcAddr));
                pktStat_inc(&eva->ipv4_dst_addr, inet_ntoa(ipv4->dstAddr));
                char pt[2];
                sprintf(pt, "%d", ipv4->protocol);
                pktStat_inc(&eva->ipv4_proto_stat, pt);
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
                    pktStat_inc(&eva->tcp_src_port, port);
                    sprintf(port, "%d", tcp->dport);
                    pktStat_inc(&eva->tcp_port_stat, port);
                    pktStat_inc(&eva->tcp_dst_port, port);
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
                pktStat_inc(&eva->udp_src_port, port);
                sprintf(port, "%d", udp->dport);
                pktStat_inc(&eva->udp_port_stat, port);
                pktStat_inc(&eva->udp_dst_port, port);
            }
        }
        // printf("=======================================================================\n");

        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset

        packet_counter++;
    } 
    pcap_close(handle);


#ifdef WRITE 
    fIP = fopen("output/ip_raw.txt", "w+");
    FILE *pure_ip = fopen("output/ip_without_counter.txt", "w+");
    fproto = fopen("output/proto_raw.txt", "w+");
    ftcpPort = fopen("output/tcp_raw.txt", "w+");
    fudpPort = fopen("output/udp_raw.txt", "w+");
#endif

    /* Check eva result */
    const char *key;
    map_iter_t iter = map_iter(&eva->eth_addr_stat);
    //printf("=======================================================================\n");
    //printf("MAC Address Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->eth_addr_stat, &iter))) {
        // printf("%s -> %d\n",  ether_ntoa((struct ether_addr*)key), *map_get(&eva->eth_addr_stat, key));
    }
    iter = map_iter(&eva->eth_type_stat);
    //printf("=======================================================================\n");
    //printf("EtherType Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->eth_type_stat, &iter))) {
        // printf("%s -> %d\n", key, *map_get(&eva->eth_type_stat, key));
    }
    iter = map_iter(&eva->ipv4_addr_stat);
    //printf("=======================================================================\n");
    //printf("IP Address Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->ipv4_addr_stat, &iter))) {
        // printf("%s -> %d\n", key, *map_get(&eva->ipv4_addr_stat, key));
#ifdef WRITE
        fprintf(fIP, "%s %d\n", key, *map_get(&eva->ipv4_addr_stat, key));
        fprintf(pure_ip, "%s\n", key);
#endif 
        // Unique count 
        unique_hosts++;
    }

    iter = map_iter(&eva->ipv4_src_addr);
    while((key=map_next(&eva->ipv4_src_addr, &iter))){
        uniq_src_ip++;
    }

    iter = map_iter(&eva->ipv4_dst_addr);
    while((key=map_next(&eva->ipv4_dst_addr, &iter))){
        uniq_dst_ip++;
    }

    iter = map_iter(&eva->ipv4_proto_stat);
    //printf("=======================================================================\n");
    //printf("IP Protocol Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->ipv4_proto_stat, &iter))) {
        // printf("%s -> %d\n", key, *map_get(&eva->ipv4_proto_stat, key));
#ifdef WRITE
        fprintf(fproto, "%s %d\n", key, *map_get(&eva->ipv4_proto_stat, key));
#endif
    }
    iter = map_iter(&eva->tcp_port_stat);
    //printf("=======================================================================\n");
    //printf("TCP Port Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->tcp_port_stat, &iter))) {
        // printf("%s -> %d\n", key, *map_get(&eva->tcp_port_stat, key));
#ifdef WRITE
        fprintf(ftcpPort, "%s %d\n", key, *map_get(&eva->tcp_port_stat, key));
#endif
        uniq_tcp++;
    }
    iter = map_iter(&eva->tcp_src_port);
    while((key=map_next(&eva->tcp_src_port, &iter))){
        uniq_tcp_src++;
    }
    iter = map_iter(&eva->tcp_dst_port);
    while((key=map_next(&eva->tcp_dst_port, &iter))){
        uniq_tcp_dst++;
    }

    iter = map_iter(&eva->udp_port_stat);
    //printf("=======================================================================\n");
    //printf("UDP Port Stat: \n");
    //printf("=======================================================================\n");
    while ((key = map_next(&eva->udp_port_stat, &iter))) {
        // printf("%s -> %d\n", key, *map_get(&eva->udp_port_stat, key));
#ifdef WRITE
        fprintf(fudpPort, "%s %d\n", key, *map_get(&eva->udp_port_stat, key));
#endif
        uniq_udp++;
    }
    iter = map_iter(&eva->udp_src_port);
    while((key=map_next(&eva->udp_src_port, &iter))){
        uniq_udp_src++;
    }
    iter = map_iter(&eva->udp_dst_port);
    while((key=map_next(&eva->udp_dst_port, &iter))){
        uniq_udp_dst++;
    }

    printf("=======================================================================\n");
    printf("Number of packets: %d\n", packet_counter);
    printf("-----------------------------------------------------------------------\n");
    printf("Unique hosts: %d\n", unique_hosts);
    printf("Unique IP source: %d\n", uniq_src_ip);
    printf("Unique IP destination: %d\n", uniq_dst_ip);
    printf("-----------------------------------------------------------------------\n");
    printf("Unique TCP ports: %d\n", uniq_tcp);
    printf("Unique TCP source ports: %d\n", uniq_tcp_src);
    printf("Unique TCP destination ports: %d\n", uniq_tcp_dst);
    printf("-----------------------------------------------------------------------\n");
    printf("Unique UDP ports: %d\n", uniq_udp);
    printf("Unique UDP source ports: %d\n", uniq_udp_src);
    printf("Unique UDP destination ports: %d\n", uniq_udp_dst);
    printf("=======================================================================\n");
    return 0;
}