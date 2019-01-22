/**
 * Statistical Difference
 * - Find out B whether P{A|B} < p = 0.05 or 0.1, then identify B is anomaly or not.
 * - Check out FP/TP rate of this method 
 * 
 */
#include <map>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
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

using namespace std;

// statistics
map<string, int> ipv4_src,ipv4_dst; // src,dst
map<int, int> tcp_src, tcp_dst;     // src,dst 
map<int, int> udp_src, udp_dst;     // src,dst

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    string inputfile("");
    while((ch=getopt(argc, argv, "df:")) != -1)
    {
        switch(ch)
        {
            case 'd':
                debug=1;
                break;
            case 'f':
                inputfile = string(optarg);
                break;
        }
    }

    struct pcap_pkthdr header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];

    handle = pcap_open_offline(inputfile.c_str(), errbuf); 
    if (handle == NULL) { 
        fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.c_str()); 
        fprintf(stderr, "%s\n", errbuf);
        return(2); 
    }

    while(packet=pcap_next(handle, &header)){
        ethernet = (struct sniff_ethernet*)(packet);
        size_existed += SIZE_ETHER;

        /* ============================================= */
        /* TODO: do something on ethernet header  */
        /* ============================================= */

        // Parse IPv4
        if(ethernet->etherType == (u_short)8){
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
            size_ip = IP_HL(ipv4)*4;
            size_existed += size_ip;

            // ipv4 src
            if(ipv4_src.find(string(inet_ntoa(ipv4->srcAddr)))==ipv4_src.end()){ 
                ipv4_src[string(inet_ntoa(ipv4->srcAddr))]=1;
            } else {
                ipv4_src[string(inet_ntoa(ipv4->srcAddr))]++;
            }
            // ipv4 dst
            if(ipv4_dst.find(string(inet_ntoa(ipv4->dstAddr)))==ipv4_dst.end()){ 
                ipv4_dst[string(inet_ntoa(ipv4->dstAddr))]=1;
            } else {
                ipv4_dst[string(inet_ntoa(ipv4->dstAddr))]++;
            }

            if(size_ip < 20){
                printf("Invalid IPv4 header length: %u bytes\n", size_ip);
            } else {
                // Parse TCP 
                if(ipv4->protocol == (u_char)6){
                    tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                    size_tcp = TH_OFF(tcp)*4;
                    size_existed += size_tcp;

                    // src port
                    if(tcp_src.find(tcp->sport)==tcp_src.end()){
                        tcp_src[tcp->sport]=1;
                    } else {
                        tcp_src[tcp->sport]++;
                    }
                    // dst port
                    if(tcp_dst.find(tcp->dport)==tcp_dst.end()){
                        tcp_dst[tcp->dport]=1;
                    } else {
                        tcp_dst[tcp->dport]++;
                    }

                } else if(ipv4->protocol == (u_char)17){
                    udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                    size_udp = 8; // 8 bytes
                    size_existed += size_udp;

                    // src port
                    if(udp_src.find(udp->sport)==udp_src.end()){
                        udp_src[udp->sport]=1;
                    } else {
                        udp_src[udp->sport]++;
                    }
                    // dst port
                    if(udp_dst.find(udp->dport)==udp_dst.end()){
                        udp_dst[udp->dport]=1;
                    } else {
                        udp_dst[udp->dport]++;
                    }
                }
            }

            /* ============================================= */
            /* TODO: Other Protocol supported in protocol number.  */
            /* ============================================= */
        }
        /* ============================================= */
        /* TODO: Other Protocol supported in etherType.  */
        /* ============================================= */
        // Rest part
        payload = (char*)(packet + size_existed);
        size_existed = 0; // reset
    }

    // count total
    unsigned int Cnt=0;
    unsigned int X=0.0;

    // ipv4 src
    for (map<string, int>::iterator iter = ipv4_src.begin();
        iter != ipv4_src.end(); ++iter) 
    {
        X += iter->second;
    }

    // second iterative -> find statistical diff.
    for (map<string, int>::iterator iter = ipv4_src.begin();
        iter != ipv4_src.end(); ++iter) 
    {
        if(iter->second/(float)X > 0.05 || iter->second/(float)X > 0.01){
            cout << "[Stat Diff - Candidate] IPv4 srcAddr: " << iter->first << endl;
            Cnt++;
        }
    }

    cout << "[Stat Diff] IPv4 srcAddr number: " << Cnt << endl;

    return 0;
}