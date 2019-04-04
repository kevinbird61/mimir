/**
 * Flowlet: flow + timeout interval 
 * 
 * Only record active packets in flow level (a.k.a `flowlet`).
 * If inter-arrival time is bigger than 100ms, than it must be another new flow.
 * 
 */
#include <map>
#include <cmath>
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

typedef struct _flow_t {
    int origin; // count normally
    int sample; // count only the first packet of flowlet
    struct timeval lastSeen;
    vector<double> t_interval_queue;
} flow_t;

map<string, flow_t> pktstat;

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

                /**
                 * struct of ts:
                 * - tv_sec  (main part, using s as unit)
                 * - tv_usec (rest part, using ms as unit)
                 */

                if(pktstat.find(string(inet_ntoa(ipv4->dstAddr))) == pktstat.end()){
                    // not existd, create one for it
                    pktstat[string(inet_ntoa(ipv4->dstAddr))].lastSeen = header.ts;
                    // count 
                    pktstat[string(inet_ntoa(ipv4->dstAddr))].origin++;
                    pktstat[string(inet_ntoa(ipv4->dstAddr))].sample++;
                } else {
                    // existed, find time interval and push it into queue
                    unsigned int prev_sec=pktstat[string(inet_ntoa(ipv4->dstAddr))].lastSeen.tv_sec;
                    unsigned long int prev_usec=pktstat[string(inet_ntoa(ipv4->dstAddr))].lastSeen.tv_usec;
                    // find interval
                    prev_sec = header.ts.tv_sec - prev_sec;
                    prev_usec = header.ts.tv_usec - prev_usec;
                    
                    // check if interval is < 100ms (if true, then we don't need to count it)
                    if(prev_sec*1000+prev_usec<=100){
                        pktstat[string(inet_ntoa(ipv4->dstAddr))].origin++;
                    } else {
                        pktstat[string(inet_ntoa(ipv4->dstAddr))].origin++;
                        pktstat[string(inet_ntoa(ipv4->dstAddr))].sample++;
                    }

                    // push back
                    pktstat[string(inet_ntoa(ipv4->dstAddr))].t_interval_queue.push_back(prev_sec+(prev_usec/1000.0));
                    // update 
                    pktstat[string(inet_ntoa(ipv4->dstAddr))].lastSeen = header.ts;
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
    }

    double total_interval=0.0;
    double total_interval_std=0.0;
    int cnt=0;
    long int pktcnt_origin=0, pktcnt_sample=0;

    for(map<string, flow_t>::iterator iter=pktstat.begin();
        iter!=pktstat.end(); ++iter)
    {
        // get sampled & original count
        pktcnt_origin+=iter->second.origin;
        pktcnt_sample+=iter->second.sample;

        // sum time interval
        if(iter->second.t_interval_queue.size() > 0){
            double avg_interval=0.0;
            for(int i=0;i<iter->second.t_interval_queue.size();i++){
                avg_interval+=iter->second.t_interval_queue.at(i);
            }
            total_interval+=(avg_interval/iter->second.t_interval_queue.size());
            total_interval_std+=powf((avg_interval/iter->second.t_interval_queue.size()), 2);
            // cout << (avg_interval/iter->second.t_interval_queue.size()) << endl;
            cnt++;
        }
    }

    cout << "==============================================================" << endl;
    cout << "Avg time interval(ms): " << total_interval/cnt << endl;
    cout << "Std time interval(ms): " << sqrtf(total_interval_std/cnt - powf(total_interval/cnt, 2)) << endl;
    cout << "Original # of packets: " << pktcnt_origin << endl;
    cout << "Sampled # of packets: " << pktcnt_sample << endl;
    cout << "Using flowlet sampled to save " << (float)(pktcnt_origin - pktcnt_sample)*100/(pktcnt_origin) << " % of packets" << endl;
    cout << "==============================================================" << endl;

    for(map<string, flow_t>::iterator iter=pktstat.begin();
        iter!=pktstat.end(); ++iter)
    {
        if(iter->second.t_interval_queue.size() > 0){
            double avg_interval=0.0;
            for(int i=0;i<iter->second.t_interval_queue.size();i++){
                avg_interval+=iter->second.t_interval_queue.at(i);
            }
            avg_interval = (avg_interval/iter->second.t_interval_queue.size());
            if(avg_interval < (total_interval/cnt)-sqrtf(total_interval_std/cnt - powf(total_interval/cnt, 2))){
                cout << "[High frequency] IP: " << iter->first << endl;
            }
        }
    }

    return 0;
}