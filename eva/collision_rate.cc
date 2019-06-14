/**
 * Bitmap control program - all modules, without execute_bitmap.
 * 
 *
 */

#include <map>
#include <cmath>
#include <chrono>
#include <ctime>  
#include <vector>
#include <iostream>

extern "C"
{
#include <unistd.h>
#include <string.h>
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

double seperated_timeout = 0.1;
int table_size = 128;
int long_term_timeout = 50;
/*
map<string, map<string, int>> repo_bitmap;      // report bitmap
map<string, map<string, double>> lastSeen;      // last seen of flow (timestamp)
map<string, map<string, int>> mod1;             // module 1 - frequency and amount of packets
map<string, map<string, int>> mod2;             // module 2 - sent/recv ratio
map<string, map<string, int>> mod3;             // module 3 - counter of ICMP type 3 (for UDP flood)
map<string, map<string, int>> nopayload;        // number of packet without payload
map<string, map<string, int>> request;          // number of requests
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
map<string, map<string, u_short>> prev_dport;
map<string, map<string, int>> mod4_diffcnt;
map<string, map<string, int>> flow_mod5;        // module 5 - Amount of (SYN-ACK)
*/

// using flowID with limited table size
int         *repo_bitmap;
double      *lastSeen;
int         *mod1;
u_short     *prev_dport;
int         *mod4_diffcnt;
int         *mod5;
// collision checker
string      *c_srcIP;
string      *c_dstIP;
int         total=0, collision=0;

chrono::time_point<std::chrono::system_clock> t_start, t_end;

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
    t_start = chrono::system_clock::now();
    int ch,input_type=0,extract=0,debug=0;
    vector<string> inputfile;
    while((ch=getopt(argc, argv, "ds:l:t:f:1:2:3:4:5:")) != -1)
    {
        switch(ch)
        {
            case 's':
                // seperated timeout 
                seperated_timeout=atof(optarg);
                break;
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
            case 't':
                table_size=atoi(optarg);
                break;
            case 'l':
                long_term_timeout=atoi(optarg);
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

    // allocate memory for each array 
    repo_bitmap = (int *)malloc(table_size*sizeof(int));
    lastSeen = (double *)malloc(table_size*sizeof(double));
    mod1 = (int *)malloc(table_size*sizeof(int));
    prev_dport = (u_short *)malloc(table_size*sizeof(u_short));
    mod4_diffcnt = (int *)malloc(table_size*sizeof(int));
    mod5 = (int *)malloc(table_size*sizeof(int));
    memset(repo_bitmap,0,sizeof(repo_bitmap));
    memset(lastSeen,0,sizeof(lastSeen));
    memset(mod1,0,sizeof(mod1));
    memset(prev_dport,0,sizeof(prev_dport));
    memset(mod4_diffcnt,0,sizeof(mod4_diffcnt));
    memset(mod5,0,sizeof(mod5));
    c_srcIP = (string *)malloc(table_size*sizeof(string));
    c_dstIP = (string *)malloc(table_size*sizeof(string));
    for(int i=0;i<table_size;i++){
        c_srcIP[i]="null";
        c_dstIP[i]="null";
    }

    struct pcap_pkthdr header; 
    const u_char *packet;
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];

    // Define variables used in each iteration
    // bi-direction
    int exec_bitmap_val=0;

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

    t_end = chrono::system_clock::now();
    chrono::duration<double> elapsed_seconds = t_end-t_start;
    time_t end_time = chrono::system_clock::to_time_t(t_end);

    cout << "=====================================================" << endl;
    cout << "Finished at " << ctime(&end_time)
              << "Elapsed time: " << elapsed_seconds.count() << " (sec)\n";
    cout << "=====================================================" << endl;


    cout << "Table size: " << table_size << endl;
    cout << "Collision rate: " << collision/(float)total << endl;
    cout << "Seperated timeout (sec): " << seperated_timeout << endl;
    cout << "Long-term timeout (sec): " << long_term_timeout << endl;
    cout << "=====================================================" << endl;

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
        unsigned int flowIndex = (crc32((unsigned char *)flowID.c_str()))%table_size;
        
        // Define variables used in each iteration
        int repo_bitmap_val=0;
        // port 
        u_short srcPort=0, dstPort=0;

        // Step3: execute each module defined by bitmap - get lastSeen 
        double lastseen_ts, interval=0;
        if(lastSeen[flowIndex]==0){
            lastseen_ts = 0;
        } else {
            lastseen_ts=lastSeen[flowIndex];
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

        if(interval > long_term_timeout ) {
            // > 10 sec, reset 
            c_srcIP[flowIndex]="null";
            c_dstIP[flowIndex]="null";
        }
        
        if(interval > seperated_timeout && (lastseen_ts!=0)){
            
        } else {
            // collision checker
            if(c_srcIP[flowIndex]=="null"|| c_dstIP[flowIndex]=="null"){
                // do nothing, initialize state
            }
            else if(c_srcIP[flowIndex]!=srcIP || c_dstIP[flowIndex]!=dstIP){
                collision++;
            } 
            total++;
            // update
            c_srcIP[flowIndex]=srcIP;
            c_dstIP[flowIndex]=dstIP;
        }

        // update lastseen (Need to wait until all module has been finished)
        lastSeen[flowIndex]=(header->ts.tv_sec + header->ts.tv_usec/1000.0);
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