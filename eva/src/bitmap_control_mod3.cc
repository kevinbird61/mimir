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
#include "../lib/hash.h"
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
map<string, map<string, int>> mod3;             // module 3 - counter of ICMP type 3 (for UDP flood)

vector<int> amount_count;
// threshold 
int cnt_threshold=10;

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:p:")) != -1)
    {
        switch(ch)
        {
            case 'p':
                cnt_threshold=atoi(optarg);
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
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                u_int size_udp = 8; // 8 bytes
                size_existed += size_udp;

                /* ============================================= */
                /* UDP              */
                /* ============================================= */
            } else if(ipv4->protocol == (u_char)1){
                /* ============================================= */
                /* ICMP              */
                /* ============================================= */
                icmp = (struct sniff_icmp*)(packet + SIZE_ETHER + size_ip);
                u_int size_icmp = 4; // 4 bytes
                size_existed += size_icmp;

                if(exec_bitmap_val&1){
                    if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                        // read from mod3
                        int icmp_unreachable=mod3[srcIP][dstIP];

                        if(icmp_unreachable > cnt_threshold){
                            // set report_bitmap
                            repo_bitmap_val|=1;
                            // update exec_bitmap
                            exec_bitmap[srcIP][dstIP]|=2;

                            // reset
                            mod3[srcIP][dstIP]=0;
                        } 

                        // FIXME: need to reset? or just maintain
                    } else {
                        // update 
                        if(icmp->type == (u_char)3 || icmp->type == (u_char)11 || icmp->type == (u_char)12){
                            if(mod3[srcIP].find(dstIP)==mod3[srcIP].end()){
                                mod3[srcIP][dstIP]=1;
                            } else {
                                mod3[srcIP][dstIP]++;
                            }
                        }
                    }
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