/**
 * Bitmap control program - all modules, without execute_bitmap.
 * 
 *
 */

#include <map>
#include <cmath>
#include <vector>
#include <iostream>

extern "C"
{
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "packet_def.h"
#include "lib/hash.h"
#include "hash/xxhash.h" 
}

// ethernet 
#define SIZE_ETHER 14
const struct sniff_ethernet *ethernet=NULL; // ethernet header
const struct sniff_ipv4 *ipv4=NULL; // IPv4 header
const struct sniff_tcp *tcp=NULL;   // TCP header
const struct sniff_udp *udp=NULL;   // UDP header
const struct sniff_icmp *icmp=NULL; // ICMP header
const char *payload; // packet payload
u_int size_existed=0;

using namespace std;

/* define stateful variables
 - using map structure (represent hash table)
 - key: hash id (src,dst IP pair)

 value of bitmap represent the number of modules
*/
#define FLOWLET_TIMEOUT 0.1

vector<int> amount_count;
map<string, map<string, int>> repo_bitmap;      // report bitmap
map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp)
map<string, map<string, int>> mod1;             // module 1 - frequency and amount of packets
map<string, map<string, int>> mod2;             // module 2 - sent/recv ratio
map<string, map<string, int>> mod3;             // module 3 - counter of ICMP type 3 (for UDP flood)
typedef struct _mod4_t {
    int prev_sport;
    int prev_dport;
    int cnt;
    int src_aoc_port; // amount of change
    int dst_aoc_port; 
    map<u_short, int> src_uniq;
    map<u_short, int> dst_uniq;
} mod4_t;
map<string, map<string, mod4_t>> mod4;          // module 4 - flowlevel unique port (by calculating hamming distance/ or directly take the difference between sequential packets)
map<string, map<string, int>> flow_mod5;        // module 5 - Amount of (SYN-ACK)

// threshold 
int threshold_1 = 50;
// float threshold_2 = 4.5; // ratio
int threshold_2 = 1000;
int threshold_3 = 50;
int threshold_4 = 10000;
int threshold_5 = 50;

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:1:2:3:4:5:")) != -1)
    {
        switch(ch)
        {
            case '1':
                threshold_1=atoi(optarg);
                break;
            case '2':
                threshold_2=atoi(optarg);
                break;
            case '3':
                threshold_3=atoi(optarg);
                break;
            case '4':
                threshold_4=atoi(optarg);
                break;
            case '5':
                threshold_5=atoi(optarg);
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

    // Define variables used in each iteration
    // bi-direction
    int exec_bitmap_val=0, rev_exec_bitmap_val=0;

    for(int i=0;i<inputfile.size();i++){
        cout << "Input file: " << inputfile.at(i) << endl;

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


    cout << "Threshold: " << endl;
    cout << "Module 1: " << threshold_1 << endl;
    cout << "Module 2: " << threshold_2 << endl;
    cout << "Module 3: " << threshold_3 << endl;
    cout << "Module 4: " << threshold_4 << endl;
    cout << "Module 5: " << threshold_5 << endl;

    cout << "Total flowlet ("<< FLOWLET_TIMEOUT <<" sec) report: " << amount_count.size() << endl;
    double total_amount_avg=0.0, total_amount_std=0.0, max=0;
    for(int i=0;i<amount_count.size();i++){
        total_amount_avg+=amount_count.at(i);
        total_amount_std+=pow(amount_count.at(i),2);
        if(amount_count.at(i)>max) max=amount_count.at(i);
    }
    cout << "Avg. amount per flowlet: " << total_amount_avg/amount_count.size() << endl;
    cout << "Std. amount per flowlet: " << sqrt(total_amount_std/amount_count.size() - pow(total_amount_avg/amount_count.size(), 2)) << endl;
    cout << "Max. per flowlet: " << max << endl;
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
        // string flowID;
        // flowID = string(inet_ntoa(ipv4->srcAddr)) + string(inet_ntoa(ipv4->dstAddr));
        // unsigned int flowIndex = crc32((unsigned char *)flowID.c_str());
        // get the reverse flow id
        // string rev_flowID; 
        // rev_flowID = string(inet_ntoa(ipv4->dstAddr)) + string(inet_ntoa(ipv4->srcAddr));
        // unsigned int rev_flowIndex = crc32((unsigned char *)rev_flowID.c_str());
        // Define variables used in each iteration
        int repo_bitmap_val=0;
        // port 
        u_short srcPort=0, dstPort=0;

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

        /* ============================================= */
        /* Others (L3)  */
        /* ============================================= */

        // if interval > 100ms (flowlet), detect
        
        if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
            // compare to threshold (configurable)
            if(mod1[srcIP][dstIP]>threshold_1){
                // high frequency 
                repo_bitmap_val|=1;
                // goto mod5
                if( flow_mod5[srcIP][dstIP] >= threshold_5 || flow_mod5[dstIP][srcIP] >= threshold_5 ){
                    // report
                    repo_bitmap_val |= 16;
                    // decrease
                    flow_mod5[srcIP][dstIP] = (flow_mod5[srcIP][dstIP] >= threshold_5) ? flow_mod5[srcIP][dstIP]/2 : flow_mod5[srcIP][dstIP];
                    flow_mod5[dstIP][srcIP] = (flow_mod5[dstIP][srcIP] >= threshold_5) ? flow_mod5[dstIP][srcIP]/2 : flow_mod5[dstIP][srcIP];
                }

                // goto mod2
                int sr_diff = std::abs(mod2[srcIP][dstIP] - mod2[dstIP][srcIP]);
                if(sr_diff > threshold_2){
                    repo_bitmap_val |= 2;
                    mod2[srcIP][dstIP]=0;
                    mod2[dstIP][srcIP]=0;
                }

                // goto mod4
                int diff =  std::abs( (int)mod4[srcIP][dstIP].src_uniq.size() - (int)mod4[srcIP][dstIP].dst_uniq.size() );
                if(diff >= threshold_4){
                    // report
                    repo_bitmap_val |= 8;
                    // reset aoc
                    mod4[srcIP][dstIP].src_uniq.clear();
                    mod4[srcIP][dstIP].dst_uniq.clear();
                }

            } else {
                // low frequency
                // goto mod3
                if(mod3[srcIP][dstIP] > threshold_3){
                    // set report_bitmap
                    repo_bitmap_val|=4;
                    // reset
                    mod3[srcIP][dstIP]=0;
                } 

                // goto mod2
                int sr_diff = std::abs(mod2[srcIP][dstIP] - mod2[dstIP][srcIP]);
                if(sr_diff > threshold_2){
                    repo_bitmap_val |= 2;

                    mod2[srcIP][dstIP]=0;
                    mod2[dstIP][srcIP]=0;
                }

                /*float sr_ratio=0.0;
                if(mod2[srcIP][dstIP] > mod2[dstIP][srcIP]){
                    sr_ratio=mod2[dstIP][srcIP]/(float)mod2[srcIP][dstIP];
                } else if(mod2[srcIP][dstIP] < mod2[dstIP][srcIP]){
                    sr_ratio=mod2[srcIP][dstIP]/(float)mod2[dstIP][srcIP];
                }
                if(sr_ratio > threshold_2){
                    repo_bitmap_val |= 2;
                    // reset
                    mod2[srcIP][dstIP]=0;
                    mod2[dstIP][srcIP]=0;
                }*/

                // goto mod4
                int diff =  std::abs( (int)mod4[srcIP][dstIP].src_uniq.size() - (int)mod4[srcIP][dstIP].dst_uniq.size() );
                if(diff >= threshold_4){
                    // report
                    repo_bitmap_val |= 8;
                    // reset aoc
                    mod4[srcIP][dstIP].src_uniq.clear();
                    mod4[srcIP][dstIP].dst_uniq.clear();
                }
            }
            amount_count.push_back(mod1[srcIP][dstIP]);
            // reset the state 
            mod1[srcIP][dstIP]=1;
        } else {
            // update mod1
            mod1[srcIP][dstIP]++;
            // update mod2
            mod2[srcIP][dstIP]++;
            // update mod3
            if(icmp!=NULL){
                if(icmp->type == (u_char)3 || icmp->type == (u_char)11 || icmp->type == (u_char)12){
                    mod3[srcIP][dstIP]++;
                }
            }
            // update mod4
            mod4[srcIP][dstIP].src_uniq[srcPort]++;
            mod4[srcIP][dstIP].dst_uniq[dstPort]++;
            // update mod5
            if(tcp!=NULL){
                if(tcp->flags&TH_RST){
                    // RST
                    flow_mod5[srcIP][dstIP]++;
                    flow_mod5[dstIP][srcIP]++;
                }
            }
        }

        // check report_bitmap value
        if(repo_bitmap_val>1){
            if(repo_bitmap_val==repo_bitmap[srcIP][dstIP]){
                // no need to report 
            } else {
                // report, and record 
                cout << srcIP << "->" << dstIP << ". Report_bitmap: " << repo_bitmap_val << endl;
                repo_bitmap[srcIP][dstIP]=repo_bitmap_val;
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
    tcp=NULL;
    udp=NULL;
    icmp=NULL;
}