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

double separated_timeout=0.1;
double start_of_pcap=10000000000, end_of_pcap=-10000000;

map<string, map<string, int>> repo_bitmap;      // report bitmap
map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp) 
vector<double> interval_q;
vector<double> sampled_interval_q;              //
int sampled_pkt=0;
vector<double> sampled_pkt_duration_q;
vector<double> avg_sampled_pkt_q;
vector<double> avg_sampled_pkt_duration_q;
vector<double> detect_interval_q;               //

// threshold 
int pktcnt_threshold=50;

int all=0,sampled=0,detect=0;

// packet process function
void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

int main(int argc, char **argv){
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "df:p:t:")) != -1)
    {
        switch(ch)
        {
            case 't':
                separated_timeout=atof(optarg);
                break;
            case 'p':
                pktcnt_threshold=atoi(optarg);
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

    cout << "Separated timeout(sec): " << separated_timeout << endl;
    cout << "Sampled rate: " << sampled/(float)all << endl;
    cout << "Detection rate: " << detect/(float)all << endl;
    cout << "Total pcap duration: " << end_of_pcap-start_of_pcap << endl;

    double avg_interval=0;
    for(auto i=0;i<interval_q.size();i++){
        avg_interval+=interval_q.at(i);
    }
    cout << "Avg. inter-arrival time: " << avg_interval/interval_q.size() << endl;
    avg_interval=0;
    for(auto i=0;i<sampled_interval_q.size();i++){
        avg_interval+=sampled_interval_q.at(i);
    }
    cout << "Avg. sampled inter-arrival time: " << avg_interval/sampled_interval_q.size() << endl;
    avg_interval=0;
    for(auto i=0;i<detect_interval_q.size();i++){
        avg_interval+=detect_interval_q.at(i);
    }
    cout << "Avg. detection inter-arrival time: " << avg_interval/detect_interval_q.size() << endl;
    for(auto i=0;i<avg_sampled_pkt_duration_q.size();i++){
        avg_interval+=avg_sampled_pkt_duration_q.at(i);
    }
    cout << "Avg. duration of each S (holding time): " << avg_interval/avg_sampled_pkt_duration_q.size() << endl;
    double avg_pkt=0, first_10percent_reward=0, cnt=0;
    for(auto i=0;i<avg_sampled_pkt_q.size();i++){
        if(i==0)
            cout << "Pkt count in S1 (holding time): " << avg_sampled_pkt_q.at(i) << endl;
        if(cnt<(0.1)*avg_sampled_pkt_q.size())
            first_10percent_reward+=avg_sampled_pkt_q.at(i);
        cnt++;
        avg_pkt+=avg_sampled_pkt_q.at(i);
    }
    cout << "Avg. pkt count in first 10% S (holding time): " << first_10percent_reward/(avg_sampled_pkt_q.size()/10) << endl;
    cout << "Avg. pkt count in each S (holding time): " << avg_pkt/avg_sampled_pkt_q.size() << endl;

    return 0;
}

void pkt_process(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    /* ============================================= */
    /* Ethernet  */
    /* ============================================= */
    ethernet = (struct sniff_ethernet*)(packet);
    size_existed += SIZE_ETHER;

    if( start_of_pcap > (header->ts.tv_sec + header->ts.tv_usec/1000.0)){ start_of_pcap=header->ts.tv_sec + header->ts.tv_usec/1000.0; }
    if( end_of_pcap < (header->ts.tv_sec + header->ts.tv_usec/1000.0)){ end_of_pcap=header->ts.tv_sec + header->ts.tv_usec/1000.0; }

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

        if(lastseen_ts!=0)
            interval_q.push_back(interval);

        if(interval > separated_timeout && (lastseen_ts!=0)){
            detect++;
            detect_interval_q.push_back(interval);
            //if(sampled_pkt_duration_q.size()!=0)
                avg_sampled_pkt_q.push_back(sampled_pkt_duration_q.size());
            double duration=0;
            for(auto i=0;i<sampled_pkt_duration_q.size();i++){
                duration+=sampled_pkt_duration_q.at(i);
            }
            avg_sampled_pkt_duration_q.push_back(duration);
            sampled_pkt_duration_q.clear();
        } else {
            sampled++;
            if(lastseen_ts!=0 && interval > 0) {// skip the negative ones
                sampled_interval_q.push_back(interval);
                sampled_pkt_duration_q.push_back(interval);
            }
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