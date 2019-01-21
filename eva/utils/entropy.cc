/*
    Utils - find entropy
*/
#include <map>
#include <cmath>
#include <string>
#include <cstring>
#include <fstream>
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

                    if(size_tcp < 20){
                        printf("Invalid TCP header length: %u bytes\n", size_tcp);
                    } else {
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
        }
        // Rest part
        payload = (char*)(packet + size_existed);
        size_existed = 0; // reset
    }
    pcap_close(handle);

    // count mean & variance & standard deviation
    unsigned int Cnt=0;
    float X=0.0, Xpow=0.0;  // E[X], E[X^2]
    float entropy=0.0;
    float mean, var, std;
    // ipv4 src
    for (map<string, int>::iterator iter = ipv4_src.begin();
        iter != ipv4_src.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }

    // second iterative -> cal entropy 
    for (map<string, int>::iterator iter = ipv4_src.begin();
        iter != ipv4_src.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }

    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] IPv4 source address: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] IPv4 source address: " << mean << endl;
    cout << "[Var] IPv4 source address: " << var << endl;
    cout << "[StD] IPv4 source address: " << std << endl;
}
    // reset
    Cnt=0;
    X=0.0, Xpow=0.0, entropy=0.0;

    // ipv4 dst
    for (map<string, int>::iterator iter = ipv4_dst.begin();
        iter != ipv4_dst.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }
    // second iterative -> cal entropy 
    for (map<string, int>::iterator iter = ipv4_dst.begin();
        iter != ipv4_dst.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }
    
    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] IPv4 destination address: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] IPv4 destination address: " << mean << endl;
    cout << "[Var] IPv4 destination address: " << var << endl;
    cout << "[StD] IPv4 destination address: " << std << endl;
}
    // reset
    Cnt=0;
    X=0.0, Xpow=0.0, entropy=0.0;

    // tcp src
    for (map<int, int>::iterator iter = tcp_src.begin();
        iter != tcp_src.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }
    // second iterative -> cal entropy 
    for (map<int, int>::iterator iter = tcp_src.begin();
        iter != tcp_src.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }

    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] TCP source Port: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] TCP source Port: " << mean << endl;
    cout << "[Var] TCP source Port: " << var << endl;
    cout << "[StD] TCP source Port: " << std << endl;
}
    // reset
    Cnt=0;
    X=0.0, Xpow=0.0, entropy=0.0;
    // tcp dst
    for (map<int, int>::iterator iter = tcp_dst.begin();
        iter != tcp_dst.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }
    // second iterative -> cal entropy 
    for (map<int, int>::iterator iter = tcp_dst.begin();
        iter != tcp_dst.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }
    
    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] TCP destination Port: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] TCP destination Port: " << mean << endl;
    cout << "[Var] TCP destination Port: " << var << endl;
    cout << "[StD] TCP destination Port: " << std << endl;
}
    // reset
    Cnt=0;
    X=0.0, Xpow=0.0, entropy=0.0;

    // udp src
    for (map<int, int>::iterator iter = udp_src.begin();
        iter != udp_src.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }
    // second iterative -> cal entropy 
    for (map<int, int>::iterator iter = udp_src.begin();
        iter != udp_src.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }

    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] UDP source Port: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] UDP source Port: " << mean << endl;
    cout << "[Var] UDP source Port: " << var << endl;
    cout << "[StD] UDP source Port: " << std << endl;
}
    // reset
    Cnt=0;
    X=0.0, Xpow=0.0, entropy=0.0;
    // udp dst
    for (map<int, int>::iterator iter = udp_dst.begin();
        iter != udp_dst.end(); ++iter) 
    {
        X += iter->second;
        Xpow += pow(iter->second, 2);
        Cnt++;
    }
    // second iterative -> cal entropy 
    for (map<int, int>::iterator iter = udp_dst.begin();
        iter != udp_dst.end(); ++iter) 
    {
        entropy += (iter->second/X)*log2f(iter->second/X);
    }
    
    mean = X/Cnt;
    var = Xpow/Cnt - pow(X/Cnt,2);
    std = sqrt(var);
    cout << "===========================================================" << endl;
    cout << "Entropy Range : 0~" << log2(Cnt) << endl;
    cout << "===========================================================" << endl;
    cout << "[Entropy] UDP destination Port: " << (-entropy) << endl;
if(debug){
    cout << "[Mean] UDP destination Port: " << mean << endl;
    cout << "[Var] UDP destination Port: " << var << endl;
    cout << "[StD] UDP destination Port: " << std << endl;
}
    return 0;
}