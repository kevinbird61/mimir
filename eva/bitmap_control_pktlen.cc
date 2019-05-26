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

map<string, map<string, int>> repo_bitmap;      // report bitmap
map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp)
map<string, map<string, int>> mod1;
map<string, map<string, int>> pktlen;           // pktlen
map<string, map<string, int>> report;   

vector<int> amount_count;
// threshold 
int cusum_threshold=2500;

int all,sampled;

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
                cusum_threshold=atoi(optarg);
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

    for(map<string, map<string,int>>::iterator i=report.begin(); i!=report.end(); i++){
        for(map<string, int>::iterator j=i->second.begin(); j!=i->second.end(); j++){
            // if(j->second > 1000)
                cout << i->first << "->" << j->first << ": " << j->second << endl;
        }
    }

    cout << "Sampled rate: " << sampled/(float)all << endl;

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

        // Define variables used in each iteration
        int repo_bitmap_val=0;
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

        if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
            // time interval > TIMEOUT
            // check report_bitmap value
            /*if(mod1[srcIP][dstIP] > 100){
                // high frequency
                if(pktlen[srcIP][dstIP] >= mod1[srcIP][dstIP]){
                    // report
                    report[srcIP][dstIP]++;
                }
                // reset all 
                mod1[srcIP][dstIP]=0;
                pktlen[srcIP][dstIP]=0;
            } else {
                // low frequency
                // do nothing, just waiting
            }*/
            
            // mod1[srcIP][dstIP]++;

            // report
            if((pktlen[srcIP][dstIP]*pktlen[srcIP][dstIP])/(mod1[srcIP][dstIP]+1) >= cusum_threshold ){
                report[srcIP][dstIP]++;
            }

            // pktlen[srcIP][dstIP]=0;
            // mod1[srcIP][dstIP]=0;

        } else {
            // do increase
            if(header->len > 1500){
                // pktlen[srcIP][dstIP]--;
            } else if(header->len < 100){
                pktlen[srcIP][dstIP]++;
            }
            // increase mod1 
            mod1[srcIP][dstIP]++;

            sampled++;
        }

        all++;
        /* ============================================= */
        /* Others (L3)  */
        /* ============================================= */

        

        // update lastseen (Need to wait until all module has been finished)
        lastSeen[srcIP][dstIP]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
    }
    /* ============================================= */
    /* Others (L2)  */
    /* ============================================= */
    payload = (char*)(packet + size_existed);
    size_existed = 0; // reset
}