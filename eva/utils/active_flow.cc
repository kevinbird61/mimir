/**
 * Evaluation how many active flows in a period of time.
 */
#include <new>          // std::bad_alloc
#include <map>
#include <cmath>
#include <vector>
#include <iostream>
#include <algorithm>

extern "C"
{
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "packet_def.h"
#include "../lib/hash.h"
#include "../lib/hamming.h"
#include "hash/xxhash.h" 
}

// ethernet 
#define SIZE_ETHER 14
const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const struct sniff_icmp *icmp; // ICMP header
const char *payload; // packet payload
u_int size_existed=0;

using namespace std;

/* define stateful variables
 - using map structure (represent hash table)
 - key: hash id (src,dst IP pair)

 value of bitmap represent the number of modules
*/
#define FLOWLET_TIMEOUT 0.1

map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp)

typedef struct _flow_t {
    // string srcIP;
    // string dstIP;
    string srcdstIP;
    double ts;
} flow_t;

bool compareTS(flow_t i1, flow_t i2) 
{ 
    // let the smallest one be the last
    return (i1.ts > i2.ts); 
} 

vector<flow_t> timeline;
map<double, vector<flow_t>> active_flow_cnt;

// useless
int upperbound=1000, lowerbound=0;
int use_long_term=1, cdf=0;
double long_term_timeout=50; // default to 50 sec

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "cndf:u:l:t:")) != -1)
    {
        switch(ch)
        {
            case 'c':
                // enable cdf output
                cdf=1;
                break;
            case 'n':
                // no long-term
                use_long_term=0;
                break;
            case 't':
                // long-term timeout
                long_term_timeout=atof(optarg);
                break;
            case 'u':
                // upperbound
                upperbound=atoi(optarg);
                break;
            case 'l':
                lowerbound=atoi(optarg);
                break;
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

    cout << timeline.max_size() << endl;

    for(int i=0;i<inputfile.size();i++){
        // cout << "Input file: " << inputfile.at(i) << endl;

        handle = pcap_open_offline(inputfile.at(i).c_str(), errbuf); 
        if (handle == NULL) { 
            fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
            fprintf(stderr, "%s\n", errbuf);
            return(2); 
        }
        // run 
        try {
            pcap_loop(handle, 0, pkt_process, NULL);
        } catch (std::bad_alloc& e) {
            cout << "#bad_alloc when pcap_loop(): " << e.what() << endl;
            cout << "#Timeline size: " << timeline.size() << endl;
        }
        // close
        pcap_close(handle);
    }

    // Finished: 
    lastSeen.clear();
    cout << "#Timeline size when finished: " << timeline.size() << endl;
    
    // sort it
    try { 
        sort(timeline.begin(), timeline.end(), compareTS);
    } catch (exception& e) {
        cout << "#sort: " << e.what() << endl;
    }

    cout << "#Finish sorting."  << endl;

    // Calculate
    try {
        double first_ts=timeline.back().ts, range=1.0; // 1 sec
        while(timeline.size() > 0){
            flow_t curr_pkt = timeline.back();
            double ts = curr_pkt.ts;
            // record 
            try {
                active_flow_cnt[(int)(ts-first_ts)/range].push_back(curr_pkt);
            } catch (std::bad_alloc& e) {
                cout << "#bad_alloc active_flow_cnt<>: " << e.what() << endl;
            }
            //cout << ts << endl;
            // pop back
            timeline.pop_back();
        }
    } catch (exception& e){
        cout << "#active_flow_cnt & timeline: " << e.what() << endl;
    }

    // finish
    cout << "#Finish timeline pop out."  << endl;

    for(map<double, vector<flow_t>>::iterator i=active_flow_cnt.begin(); i!=active_flow_cnt.end(); i++)
    {
        map<string, int> period_active_flow;

        try {
            for(int j=0;j<i->second.size();j++){
                period_active_flow[i->second.at(j).srcdstIP]++;
            }
        } catch (std::bad_alloc& e) {
            cout << "#bad_alloc period_active_flow<>: " << e.what() << endl;
        }

        /*int flowsize=0;
        for(map<string, int>::iterator p=period_active_flow.begin(); p!=period_active_flow.end(); p++)
        {
            flowsize+=p->second.size();
            // for(map<string, int>::iterator d=p->second.begin(); d!=p->second.end(); d++){}
        }*/

        cout << i->first << ": " << period_active_flow.size() << endl; 
    }

    // cout << "# UNIQUE Number's upperbound: " << upperbound << ", lowerbound: " << lowerbound << endl;

    return 0;
}

void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* ============================================= */
    /* Ethernet  */
    /* ============================================= */
    ethernet = (struct sniff_ethernet*)(packet);
    size_existed += SIZE_ETHER;

    // Parse IPv4
    if(ethernet->etherType == (u_short)8){
        ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
        u_int size_ip = IP_HL(ipv4)*4;
        size_existed += size_ip;

        // Step1: Get flow id
        string srcIP = string(inet_ntoa(ipv4->srcAddr));
        string dstIP = string(inet_ntoa(ipv4->dstAddr));
        // Step3: execute each module defined by bitmap - get lastSeen 
        double lastseen_ts, interval=0;
        if(lastSeen[srcIP].find(dstIP)==lastSeen[srcIP].end()){
            //lastSeen[srcIP][dstIP]=0;
            lastseen_ts = 0;
        } else {
            lastseen_ts=lastSeen[srcIP][dstIP];
        }
        // interval
        interval = (header->ts.tv_sec + header->ts.tv_usec/1000.0) - lastseen_ts;

        // port 
        u_short srcPort=0, dstPort=0;

        if(size_ip < 20){
            printf("Invalid IPv4 header length: %u bytes\n", size_ip);
        } else {
            // Parse TCP 
            if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                u_int size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;
                /* ============================================= */
                /* TCP              */
                /* ============================================= */
                srcPort=tcp->sport;
                dstPort=tcp->dport;

            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                u_int size_udp = 8; // 8 bytes
                size_existed += size_udp;

                /* ============================================= */
                /* UDP              */
                /* ============================================= */
                srcPort=udp->sport;
                dstPort=udp->dport;
                
            } else if(ipv4->protocol == (u_char)1){
                /* ============================================= */
                /* ICMP              */
                /* ============================================= */
                icmp = (struct sniff_icmp*)(packet + SIZE_ETHER + size_ip);
                u_int size_icmp = 4; // 4 bytes
                size_existed += size_icmp;
            }
        }

        // record the first seen 
        flow_t new_record;
        new_record.srcdstIP=srcIP+dstIP;
        new_record.ts=header->ts.tv_sec+(header->ts.tv_usec/1000.0);
        // push into timeline
        timeline.push_back(new_record);
        
        // update lastseen (Need to wait until all module has been finished)
        lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
    }
    /* ============================================= */
    /* Others (L2)  */
    /* ============================================= */
    payload = (char*)(packet + size_existed);
    size_existed = 0; // reset
}