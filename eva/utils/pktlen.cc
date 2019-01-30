/*
    Utils - Inspect packet length 
    (Hamming distance, different count on packet length)
    (Sketching)
*/
#include <map>
#include <cmath>
#include <string>
#include <cstring>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

// using c library 
extern "C" {
#include "packet_def.h"
#include "hamming.h"
}

// ethernet 
#define SIZE_ETHER 14
const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const char *payload; // packet payload
u_int size_ip, size_tcp, size_udp, size_existed=0;

using namespace std;

// Pktlen data structure
typedef struct _pktlen_t {
    uint32_t    total_dist;     // totally change
    uint32_t    total_num;      // number of changing 
    uint16_t    last_pktlen;    // previous pktlen
} pktlen_t;

// Using MAP as our KV table
map<string, pktlen_t> pktlen_tb;

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

    uint16_t pktlen;

    while(packet=pcap_next(handle, &header)){
        // get the pktlen
        pktlen = header.len;

        // Parsing Ethernet
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
            if(pktlen_tb.find(string(inet_ntoa(ipv4->srcAddr)))==pktlen_tb.end()){ 
                // initializing state
                pktlen_t newnode;
                newnode.total_dist=0;
                newnode.total_num=0;
                newnode.last_pktlen=pktlen;
                // assign
                pktlen_tb[string(inet_ntoa(ipv4->srcAddr))]=newnode;
            } else {
                // updating state
                uint16_t prev_pktlen = pktlen_tb[string(inet_ntoa(ipv4->srcAddr))].last_pktlen;
                // update 
                pktlen_tb[string(inet_ntoa(ipv4->srcAddr))].total_dist+=popcount32_fast_mul(prev_pktlen^pktlen);
                pktlen_tb[string(inet_ntoa(ipv4->srcAddr))].total_num++;
                pktlen_tb[string(inet_ntoa(ipv4->srcAddr))].last_pktlen=pktlen;
            }


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

    cout << "Leverage Hamming distance and Sketching to inspect packet length and find out the botnet." << endl;

    // collect the statistics
    float X=0.0, Xpow=0.0;
    float mean=0.0, var=0.0, std=0.0;
    
    // first iterative 
    for(map<string, pktlen_t>::iterator iter=pktlen_tb.begin();
        iter!=pktlen_tb.end(); ++iter)
    {
        X += iter->second.total_dist;
        Xpow += powf(iter->second.total_dist, 2);
    }

    mean = X/pktlen_tb.size();
    var = Xpow/pktlen_tb.size() - powf(X/pktlen_tb.size(),2);
    std = sqrtf(var);

    map<string, uint32_t> ft1, ft2, ft3; // different threshold filter

    for(map<string, pktlen_t>::iterator iter=pktlen_tb.begin();
        iter!=pktlen_tb.end(); ++iter)
    {
        if(iter->second.total_dist > (mean + 3*std))
            ft3[iter->first]=iter->second.total_dist;
        if(iter->second.total_dist > (mean + 2*std))
            ft2[iter->first]=iter->second.total_dist;
        if(iter->second.total_dist > (mean + std))
            ft1[iter->first]=iter->second.total_dist;
    }

    cout << "===========================================================" << endl;
    cout << "Threshold: MEAN + 3*STD" << endl;
    cout << "===========================================================" << endl;
    for(map<string, uint32_t>::iterator iter=ft3.begin();
        iter!=ft3.end(); ++iter)
    {
            cout << "[IP: " << iter->first << 
                "] -> " << iter->second << "\n";
    }
    cout << "===========================================================" << endl;
    cout << "Threshold: MEAN + 2*STD" << endl;
    cout << "===========================================================" << endl;
    for(map<string, uint32_t>::iterator iter=ft2.begin();
        iter!=ft2.end(); ++iter)
    {
            cout << "[IP: " << iter->first << 
                "] -> " << iter->second << "\n";
    }
    cout << "===========================================================" << endl;
    cout << "Threshold: MEAN + STD" << endl;
    cout << "===========================================================" << endl;
    for(map<string, uint32_t>::iterator iter=ft1.begin();
        iter!=ft1.end(); ++iter)
    {
            cout << "[IP: " << iter->first << 
                "] -> " << iter->second << "\n";
    }
    cout << "===========================================================" << endl;


    return 0;
}