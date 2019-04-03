/**
 * ewma_pktlen - EWMA + packet length inspection 
 * 
 * Monitor packet length change per flow.
 * 
 */
#include <map>
#include <cmath>
#include <vector>
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

// Per-flow data structure
typedef struct _flow_t {
    int prev_pktlen;
    float delta;
} flow_t;

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

    map<string, flow_t> flow;

    int psize=0, lsize=0;

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
            //cout << "TS: " << header.ts.tv_usec << endl;
            /*psize++;
            if(header.len > 1500){
                //cout << "Len: " << header.len << ", Caplen: " << header.caplen << endl;
                lsize++;
            }*/
            // Parse IPv4
            if(ethernet->etherType == (u_short)8){
                ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
                size_ip = IP_HL(ipv4)*4;
                size_existed += size_ip;
                /* ============================================= */
                /* TODO: do something on IPv4 header             */
                /* ============================================= */

                if(flow.find(string(inet_ntoa(ipv4->srcAddr)))==flow.end()){
                    // not existed
                    flow_t newflow;
                    newflow.delta = header.len/2.0;
                    newflow.prev_pktlen = header.len;
                    flow[string(inet_ntoa(ipv4->srcAddr))] = newflow;
                } else {
                    // existed, update
                    uint32_t prev_pktlen = flow[string(inet_ntoa(ipv4->srcAddr))].prev_pktlen;
                    float curr_delta = 0.0, prev_delta = flow[string(inet_ntoa(ipv4->srcAddr))].delta;
                    curr_delta = abs(header.len - prev_pktlen)/2.0;
                    flow[string(inet_ntoa(ipv4->srcAddr))].delta = (curr_delta + prev_delta) / 2.0;
                    flow[string(inet_ntoa(ipv4->srcAddr))].prev_pktlen = header.len;

                    cout << header.ts.tv_sec << endl;
                }

            }
            // Rest part
            payload = (char*)(packet + size_existed);
            size_existed = 0; // reset
        }
    }

    // print out the result 
    float x=0.0, xpow=0.0, mean, var, std;
    for(map<string, flow_t>::iterator iter=flow.begin();
        iter!=flow.end(); ++iter)
    {
        x += iter->second.delta;
        xpow += powf(iter->second.delta, 2);
    }

    mean = x/flow.size();
    var = xpow/flow.size() - powf(x/flow.size(), 2);
    std = sqrtf(var);

    for(map<string, flow_t>::iterator iter=flow.begin();
        iter!=flow.end(); ++iter)
    {
        if(iter->second.delta > (mean+3*std)){
            cout << iter->first << ": " << iter->second.delta << endl;
        }
    }

    return 0;
}