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
map<string, map<string, double>> rst_lastSeen;  // last seen of RST 
map<double, int> rst_interval;
vector<double> rst_interval_q;

// map<int, int> rst_dist;
vector<string> monitor_flows;

int upperbound=1000, lowerbound=0;
int use_long_term=1, cdf=0, non_log=0;
double long_term_timeout=50; // default to 50 sec

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "pcnf:u:l:t:i:")) != -1)
    {
        switch(ch)
        {
            case 'p':
                // non-log print
                non_log=1;
                break;
            case 'i':
                // IP
                optind--;
                for( ;optind < argc && *argv[optind] != '-'; optind++){
                    // push new file
                    cout << "# monitor IP: " << argv[optind] << endl;
                    monitor_flows.push_back(argv[optind]);
                }
                break;
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
        // cout << "Input file: " << inputfile.at(i) << endl;

        handle = pcap_open_offline(inputfile.at(i).c_str(), errbuf); 
        if (handle == NULL) { 
            fprintf(stderr, "Couldn't open pcap file: %s\n", inputfile.at(i).c_str()); 
            fprintf(stderr, "%s\n", errbuf);
            return(2); 
        }
        // run 
        pcap_loop(handle, 0, pkt_process, NULL);
        // close
        pcap_close(handle);
    }

    double cdf_val=0, total=0;
    // Print format:
    // <Number of Unique dst ports> <Counter>
    if(cdf){
        for(map<double, int>::iterator p=rst_interval.begin(); p!=rst_interval.end(); p++)
        {
            if(non_log)
                total+=p->second;
            else
                total+=logf(p->second);
            // cout << p->first << " " << cdf_val << endl;
        }
        for(map<double, int>::iterator p=rst_interval.begin(); p!=rst_interval.end(); p++)
        {
            if(non_log)
                cdf_val+=p->second;
            else
                cdf_val+=logf(p->second);
            cout << p->first << " " << (cdf_val/total) << endl;
        }
    } else {
        for(map<double, int>::iterator p=rst_interval.begin(); p!=rst_interval.end(); p++)
        {
            if(non_log)
                cout << p->first << " " << (p->second) << endl;
            else
                cout << p->first << " " << logf(p->second) << endl;
        }
    }

    cout << "# UNIQUE Number's upperbound: " << upperbound << ", lowerbound: " << lowerbound << endl;

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
                // mod4[srcIP][dstIP].cnt++;

                // monitor src<->dst (1-by-1)
                if(monitor_flows.size()!=0){
                    if( (std::find(monitor_flows.begin(), monitor_flows.end(), srcIP) != monitor_flows.end()) && (std::find(monitor_flows.begin(), monitor_flows.end(), dstIP) != monitor_flows.end()) ) {
                        /* match the connection we want to monitor */
                        if(tcp->flags&TH_RST){
                            // RST
                            if(rst_lastSeen[srcIP].find(dstIP)==rst_lastSeen[srcIP].end()){
                                rst_lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
                            } else {
                                // store interval
                                double rst_intv=abs((header->ts.tv_sec + header->ts.tv_usec/1000.0)-rst_lastSeen[srcIP][dstIP]);
                                
                                if(rst_intv>=0){
                                    if(rst_intv>upperbound){
                                        // upperbound
                                        rst_interval[upperbound]++;
                                    } else if(interval<1){
                                        if(rst_intv>=0 && rst_intv<0.1){
                                            rst_interval[0]++;
                                        } else if(rst_intv>0.1 && rst_intv <0.2){
                                            rst_interval[0.1]++;
                                        } else if(rst_intv>0.2 && rst_intv <0.3){
                                            rst_interval[0.2]++;
                                        } else if(rst_intv>0.3 && rst_intv <0.4){
                                            rst_interval[0.3]++;
                                        } else if(rst_intv>0.4 && rst_intv <0.5){
                                            rst_interval[0.4]++;
                                        } else if(rst_intv>0.5 && rst_intv <0.6){
                                            rst_interval[0.5]++;
                                        } else if(rst_intv>0.6 && rst_intv <0.7){
                                            rst_interval[0.6]++;
                                        } else if(rst_intv>0.7 && rst_intv <0.8){
                                            rst_interval[0.7]++;
                                        } else if(rst_intv>0.8 && rst_intv <0.9){
                                            rst_interval[0.8]++;
                                        } else if(rst_intv>0.9 && rst_intv <1){
                                            rst_interval[0.9]++;
                                        }
                                    } else {
                                        rst_interval[(int)rst_intv]++;
                                    }
                                }

                                // update
                                rst_lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
                            }
                        }
                    } else {
                        /* no match */
                        // do nothing
                    }
                } else {
                    // check
                    if(tcp->flags&TH_RST){
                        // RST
                        if(rst_lastSeen[srcIP].find(dstIP)==rst_lastSeen[srcIP].end()){
                            rst_lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
                        } else {
                            // store interval
                            double rst_intv=abs((header->ts.tv_sec + header->ts.tv_usec/1000.0)-rst_lastSeen[srcIP][dstIP]);
                            
                            if(rst_intv>=0){
                                if(rst_intv>upperbound){
                                    // upperbound
                                    rst_interval[upperbound]++;
                                } else if(interval<1){
                                    if(rst_intv>=0 && rst_intv<0.1){
                                        rst_interval[0]++;
                                    } else if(rst_intv>0.1 && rst_intv <0.2){
                                        rst_interval[0.1]++;
                                    } else if(rst_intv>0.2 && rst_intv <0.3){
                                        rst_interval[0.2]++;
                                    } else if(rst_intv>0.3 && rst_intv <0.4){
                                        rst_interval[0.3]++;
                                    } else if(rst_intv>0.4 && rst_intv <0.5){
                                        rst_interval[0.4]++;
                                    } else if(rst_intv>0.5 && rst_intv <0.6){
                                        rst_interval[0.5]++;
                                    } else if(rst_intv>0.6 && rst_intv <0.7){
                                        rst_interval[0.6]++;
                                    } else if(rst_intv>0.7 && rst_intv <0.8){
                                        rst_interval[0.7]++;
                                    } else if(rst_intv>0.8 && rst_intv <0.9){
                                        rst_interval[0.8]++;
                                    } else if(rst_intv>0.9 && rst_intv <1){
                                        rst_interval[0.9]++;
                                    }
                                } else {
                                    rst_interval[(int)rst_intv]++;
                                }
                            }

                            // update
                            rst_lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
                        }
                    }
                }
                
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                u_int size_udp = 8; // 8 bytes
                size_existed += size_udp;

                /* ============================================= */
                /* UDP              */
                /* ============================================= */
                srcPort=udp->sport;
                dstPort=udp->dport;
                // mod4[srcIP][dstIP].cnt++;
                
            } else if(ipv4->protocol == (u_char)1){
                /* ============================================= */
                /* ICMP              */
                /* ============================================= */
                icmp = (struct sniff_icmp*)(packet + SIZE_ETHER + size_ip);
                u_int size_icmp = 4; // 4 bytes
                size_existed += size_icmp;
            }
        }

        // update lastseen (Need to wait until all module has been finished)
        lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
    }
    /* ============================================= */
    /* Others (L2)  */
    /* ============================================= */
    payload = (char*)(packet + size_existed);
    size_existed = 0; // reset
}