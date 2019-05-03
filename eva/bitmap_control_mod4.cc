/**
 * Bitmap control program - execute mod1 only.
 * 
 * - use to evaluate the report rate of mod1 (e.g. influence of mod1).
 * - use flow-level to collect stats and inspect.
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
#include "lib/hamming.h"
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

map<string, map<string, int>> exec_bitmap;      // execute bitmap 
map<string, map<string, int>> repo_bitmap;      // report bitmap
map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp)

typedef struct _mod4_t {
    int prev_sport;
    int prev_dport;
    int aoc_port; // amount of change
} mod4_t;

map<string, map<string, mod4_t>> mod4;             // module 4 - flowlevel unique port (by calculating hamming distance/ or directly take the difference between sequential packets)

vector<int> amount_count;
// threshold 
int mode = 0; // 0: directly take the difference, 1: take the hamming distance
int diff_threshold=1000;

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:p:m:")) != -1)
    {
        switch(ch)
        {
            case 'm':
                // mode 
                mode=atoi(optarg);
                break;
            case 'p':
                diff_threshold=atoi(optarg);
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
        string flowID;
        flowID = string(inet_ntoa(ipv4->srcAddr)) + string(inet_ntoa(ipv4->dstAddr));
        unsigned int flowIndex = crc32((unsigned char *)flowID.c_str());
        // get the reverse flow id
        string rev_flowID; 
        rev_flowID = string(inet_ntoa(ipv4->dstAddr)) + string(inet_ntoa(ipv4->srcAddr));
        unsigned int rev_flowIndex = crc32((unsigned char *)rev_flowID.c_str());
        // Define variables used in each iteration
        int exec_bitmap_val=0, rev_exec_bitmap_val=0;
        int repo_bitmap_val=0;

        // Step2: Get the execute bitmap for this entry
        if(exec_bitmap[srcIP].find(dstIP)==exec_bitmap[srcIP].end()){
            // exec_bitmap[srcIP][dstIP]=1;
            exec_bitmap_val=1;
        } else {
            exec_bitmap_val=exec_bitmap[srcIP][dstIP];
        }

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

            // Mod4 - calculate the number of unique port
            if((exec_bitmap_val&1)){
                int diff=0;
                int prev_sport = mod4[srcIP][dstIP].prev_sport;
                int prev_dport = mod4[srcIP][dstIP].prev_dport;
                // calculate hamming 
                if(mode!=0){
                    // take hamming 
                    diff = popcount32_better(srcPort ^ prev_sport) + popcount32_better(dstPort ^ prev_dport);
                } else {
                    // directly take diff
                    diff = abs(srcPort - prev_sport) + abs(dstPort - prev_dport);
                }

                if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                    if(diff > diff_threshold){
                        // report
                        repo_bitmap_val |= 1;
                        // update exec_bitmap value
                        exec_bitmap[srcIP][dstIP] |= 2;
                    }

                    // reset aoc
                    mod4[srcIP][dstIP].aoc_port=0;
                    
                } else {
                    // update mod4 
                    if(mod4[srcIP].find(dstIP)==mod4[srcIP].end()){
                        mod4[srcIP][dstIP].aoc_port=diff;
                    } else {
                        mod4[srcIP][dstIP].aoc_port+=diff;
                    }
                    mod4[srcIP][dstIP].prev_sport=srcPort;
                    mod4[srcIP][dstIP].prev_dport=dstPort;
                }
            }

        }

        /* ============================================= */
        /* Others (L3)  */
        /* ============================================= */

        // check report_bitmap value
        if(repo_bitmap_val>=1){
            if(repo_bitmap_val==repo_bitmap[srcIP][dstIP] || repo_bitmap_val<=repo_bitmap[srcIP][dstIP]){
                // no need to report 
            } else {
                // report, and record 
                cout << srcIP << "->" << dstIP << endl;
                repo_bitmap[srcIP][dstIP]=repo_bitmap_val;
            }
        } else {
            // repo_bitmap_val < 1
            repo_bitmap[srcIP][dstIP]=0;
        }

        /*if(repo_bitmap[srcIP][dstIP]>=1){
            if(repo_bitmap[srcIP][dstIP]&4){
                cout << "TCP: SYN > ACK!" << endl;
            } else if(repo_bitmap[srcIP][dstIP]&8){
                cout << "ICMP target Unreachable!" << endl;
            }
            cout << srcIP << "-> " << dstIP << endl; 
            // reset 
            repo_bitmap[srcIP][dstIP]=0;
            // reset 
            exec_bitmap[srcIP][dstIP]=1;
        } else if(repo_bitmap[dstIP][srcIP]>=1){
            // reverse
            cout << dstIP << "<-" << srcIP << endl;
            // reset 
            repo_bitmap[dstIP][srcIP]=0;
            // reset 
            exec_bitmap[dstIP][srcIP]=1;
        }*/

        // update lastseen (Need to wait until all module has been finished)
        lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
    }
    /* ============================================= */
    /* Others (L2)  */
    /* ============================================= */
    payload = (char*)(packet + size_existed);
    size_existed = 0; // reset
}