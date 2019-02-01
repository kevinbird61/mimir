/**
 * Template: Minimal reading pcap program (C++)
 * 
 * Support: Eth, IPv4, TCP, UDP
 * 
 * Compile: g++ mini_pcap.cc -lpcap -Ilib 
 * 
 * Basic Run: ./a.out [-d] -f <pcap>
 * 
 */
#include <vector>
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

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:")) != -1)
    {
        switch(ch)
        {
            case 'd':
                debug=1;
                break;
            case 'f':
                optind--;
                for( ;optind < argc && *argv[optind] != '-'; optind++){
                    // push new file
                    inputfile.push_back(argv[optind]);
                }
                break;
        }
    }

    struct pcap_pkthdr header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];

    for(int i=0;i<inputfile.size();i++){
        cout << "Input file: " << inputfile.at(i) << endl;

        handle = pcap_open_offline(inputfile.at(i).c_str(), errbuf); 
        if (handle == NULL) { 
            fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
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

                /* ============================================= */
                /* TODO: do something on IPv4 header             */
                /* ============================================= */

                if(size_ip < 20){
                    printf("Invalid IPv4 header length: %u bytes\n", size_ip);
                } else {
                    // Parse TCP 
                    if(ipv4->protocol == (u_char)6){
                        tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                        size_tcp = TH_OFF(tcp)*4;
                        size_existed += size_tcp;
                        /* ============================================= */
                        /* TODO: do something on TCP header              */
                        /* ============================================= */

                    } else if(ipv4->protocol == (u_char)17){
                        udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                        size_udp = 8; // 8 bytes
                        size_existed += size_udp;

                        /* ============================================= */
                        /* TODO: do something on UDP header              */
                        /* ============================================= */
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
    }

    return 0;
}