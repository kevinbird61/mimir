/**
 * Using the ratio of # packets of sent/recv.
 * And based on the ratio to select the potential attackers/victims.
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

extern "C"
{
#include "../lib/hash.h"
#include "hash/xxhash.h" 
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

// Stateful memory (variables)
typedef struct _ts_t {
    string srcIP;
    string dstIP;
    double lastSeen; // In P4, need to using as many as long int to store this value (because P4 doesn't support floating point.)
} ts_t;
// | (srcIP, dstIP) | stats... |
map<unsigned int, ts_t> flow_pktts; // per-flow timestamp stats. 

typedef struct _flow_t {
    int sent;
    int recv;
} flow_t;
// | IP | stats... |
map<string, flow_t> flow_pktstats;
// Reporting
map<string, int> victim_candidates, attacker_candidates;

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
                
                int srr_flag=0;

                // timestamp 
                string flowID; // concate srcIP and dstIP (for hashing)
                flowID = string(inet_ntoa(ipv4->srcAddr)) + string(inet_ntoa(ipv4->dstAddr));
                unsigned int flowIndex = crc32((unsigned char *)flowID.c_str());
                // record src,dst IP (for tracing)
                flow_pktts[flowIndex].srcIP = string(inet_ntoa(ipv4->srcAddr));
                flow_pktts[flowIndex].dstIP = string(inet_ntoa(ipv4->dstAddr));
                // record/update timestamp
                double lastSeen = flow_pktts[flowIndex].lastSeen, current = header.ts.tv_sec + header.ts.tv_usec/1000.0;
                // check if it is new active flow or not. 0.1 s = 100 ms
                if(lastSeen!=0.0 && current-lastSeen > 0.1){
                    // need to check sent/recv ratio
                    srr_flag=1;
                }
                flow_pktts[flowIndex].lastSeen = current; // floating 
                
                // packet count for sent/recv ratio
                flow_pktstats[string(inet_ntoa(ipv4->srcAddr))].sent++;
                flow_pktstats[string(inet_ntoa(ipv4->dstAddr))].recv++;
                // if srr_flag is set, then perform sent/recv ratio checking.
                if(srr_flag){
                    // check dstAddr
                    int sentpkts=flow_pktstats[string(inet_ntoa(ipv4->dstAddr))].sent;
                    int recvpkts=flow_pktstats[string(inet_ntoa(ipv4->dstAddr))].recv;
                    if(sentpkts!=0 && recvpkts!=0){
                        float ratio = sentpkts/(float)recvpkts;
                        if(ratio <= 2/9){
                            // e.g. 1:5, 1:6 ...
                            // recognize as victim candidate
                            victim_candidates[string(inet_ntoa(ipv4->dstAddr))]++;
                        } else if (ratio >= 9/2) {
                            // e.g. 4:1, 5:1 ...
                            // recognize as attacker candidate
                            attacker_candidates[string(inet_ntoa(ipv4->dstAddr))]++;
                        }
                    }
                    // then check srcAddr
                    sentpkts=flow_pktstats[string(inet_ntoa(ipv4->srcAddr))].sent;
                    recvpkts=flow_pktstats[string(inet_ntoa(ipv4->srcAddr))].recv;
                    if(sentpkts!=0 && recvpkts!=0){
                        float ratio = sentpkts/(float)recvpkts;
                        if(ratio <= 0.25){
                            // e.g. 1:5, 1:6 ...
                            // recognize as victim candidate
                            victim_candidates[string(inet_ntoa(ipv4->srcAddr))]++;
                        } else if (ratio >= 4) {
                            // e.g. 4:1, 5:1 ...
                            // recognize as attacker candidate
                            attacker_candidates[string(inet_ntoa(ipv4->srcAddr))]++;
                        }
                    }
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

    cout << "Victim Candidates: ==========================================" << endl;
    for(map<string, int>::iterator iter=victim_candidates.begin();
        iter!=victim_candidates.end(); iter++)
    {
        cout << "IP: " << iter->first << endl;
        cout << "Index counter: " << iter->second << endl;
    }
    cout << "==============================================================" << endl;

    cout << "Attacker Candidates: ==========================================" << endl;
    for(map<string, int>::iterator iter=attacker_candidates.begin();
        iter!=attacker_candidates.end(); iter++)
    {
        cout << "IP: " << iter->first << endl;
        cout << "Index counter: " << iter->second << endl;
    }
    cout << "==============================================================" << endl;

    return 0;
}