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
#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

extern "C"
{
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "packet_def.h"
#include "../lib/hash.h"
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
double long_term_timeout = 50;

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

typedef struct _report_pairs_t {
    string srcIP;
    string dstIP;
    int type;
} report_pairs_t;

vector<report_pairs_t> report_pairs;
vector<string> anomaly_IP_list;
map<string, int> unique_IP;
map<string, map<string, int>> unique_flows;
map<string, map<string, int>> sampled_unique_flows;

int         total=0, collision=0, report_cnt=0, report_with_mitigation_cnt=0,
    sampled_pkt=0, total_pkt=0, sampled_anomaly_pkt=0, anomaly_pkt=0;

map<int,int> anomaly_burst_len_mod1;
vector<int> anomaly_burst_len_seq, benign_burst_len_seq;
map<int,int> benign_burst_len_mod1;
map<int,int> anomaly_burst_len_when_trigger_detect;

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
    string anomaly_list_file;
    vector<string> found_anomaly_list;

    while((ch=getopt(argc, argv, "ds:l:t:f:1:2:3:4:5:a")) != -1)
    {
        switch(ch)
        {
            case 'a':
                // anomaly IP list, use to calculate DR/NFA
                anomaly_list_file=argv[optind];
                break;
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
                long_term_timeout=atof(optarg);
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

    // readin anomaly list
    string line;
    ifstream infile(anomaly_list_file);
    while (infile >> line)
    {
        // store anomaly ip list
        anomaly_IP_list.push_back(line);
    }

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

    // analyze report pairs 
    int tp=0,fp=0;
    map<int, int> report_type_cnt;
    map<int, int> fp_report_type_cnt;
    for(int i=0;i<report_pairs.size();i++){
        //cout << report_pairs.at(i).srcIP << "->" << report_pairs.at(i).dstIP << endl;
        if( (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), report_pairs.at(i).srcIP) != anomaly_IP_list.end()) &&
            (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), report_pairs.at(i).dstIP) != anomaly_IP_list.end())
            ) {
            /* contains  */
            tp++;
            report_type_cnt[report_pairs.at(i).type]++;
            if( (find(found_anomaly_list.begin(), found_anomaly_list.end(), report_pairs.at(i).srcIP) == found_anomaly_list.end()) 
                ) {
                    // not existed
                    found_anomaly_list.push_back(report_pairs.at(i).srcIP);
                }
            if( (find(found_anomaly_list.begin(), found_anomaly_list.end(), report_pairs.at(i).dstIP) == found_anomaly_list.end()) 
                ) {
                    // not existed
                    found_anomaly_list.push_back(report_pairs.at(i).dstIP);
                }
        } else {
            /* does not contain x */
            fp++;
            fp_report_type_cnt[report_pairs.at(i).type]++;
            // cout << report_pairs.at(i).srcIP << "<->" << report_pairs.at(i).dstIP << endl;
        }
    }
    cout << "=====================================================" << endl;
    cout << "Number of report: " << report_pairs.size() << endl;
    cout << "Number of true positive: " << tp << endl;
    cout << "Detection rate (DR): " << found_anomaly_list.size()/(float)anomaly_IP_list.size() << endl;
    cout << "Number of false alarm (NFA): " << fp << endl;
    cout << "=====================================================" << endl;
    cout << "FP Report type summary: " << endl;
    for(map<int,int>::iterator i=fp_report_type_cnt.begin(); i!=fp_report_type_cnt.end(); i++){
        cout << i->first << ": " << i->second << endl;
    }
    cout << "-----------------------------------------------------" << endl;
    cout << "TP Report type summary: " << endl;
    for(map<int,int>::iterator i=report_type_cnt.begin(); i!=report_type_cnt.end(); i++){
        cout << i->first << ": " << i->second << endl;
    }

    // write file (anomaly/benign burst len)
    ofstream anomaly_burst_len, benign_burst_len, report_anomaly_burst_len, anomaly_burst_len_seq_f, benign_burst_len_seq_f;
    anomaly_burst_len.open("anomaly_burst_len.txt");
    anomaly_burst_len_seq_f.open("anomaly_burst_len_seq.txt");
    benign_burst_len.open("benign_burst_len.txt");
    benign_burst_len_seq_f.open("benign_burst_len_seq.txt");
    report_anomaly_burst_len.open("report_anomaly_burst_len.txt");

    double total_burst_cnt=0, interest=0;
    for(map<int,int>::iterator i=anomaly_burst_len_mod1.begin();i!=anomaly_burst_len_mod1.end();i++){
        anomaly_burst_len<<i->first<< " " << i->second << "\n";
        total_burst_cnt+=i->second;
        if(i->first>10){
            interest+=i->second;
        }
    }
    anomaly_burst_len << "#Bound: " << 10 << "\n";
    anomaly_burst_len << "# " << interest/total_burst_cnt << "\n";
    anomaly_burst_len.close();
    // reset
    total_burst_cnt=0;
    interest=0;
    for(map<int,int>::iterator i=anomaly_burst_len_when_trigger_detect.begin();i!=anomaly_burst_len_when_trigger_detect.end();i++){
        report_anomaly_burst_len<<i->first<< " " << i->second << "\n";
        total_burst_cnt+=i->second;
        if(i->first>10){
            interest+=i->second;
        }
    }
    report_anomaly_burst_len << "#Bound: " << 10 << "\n";
    report_anomaly_burst_len << "# " << interest/total_burst_cnt << "\n";
    report_anomaly_burst_len.close();
    // reset
    total_burst_cnt=0;
    interest=0;
    for(map<int,int>::iterator i=benign_burst_len_mod1.begin();i!=benign_burst_len_mod1.end();i++){
        benign_burst_len<<i->first<< " " << i->second << "\n";
        total_burst_cnt+=i->second;
        if(i->first>10){
            interest+=i->second;
        }
    }
    benign_burst_len << "# " << interest/total_burst_cnt << "\n";
    benign_burst_len.close();
    for(auto i=0;i<anomaly_burst_len_seq.size();i++){
        anomaly_burst_len_seq_f << i << " " << anomaly_burst_len_seq.at(i) << "\n";
    }
    anomaly_burst_len_seq_f.close();
    for(auto i=0;i<benign_burst_len_seq.size();i++){
        benign_burst_len_seq_f << i << " " << benign_burst_len_seq.at(i) << "\n";
    }
    benign_burst_len_seq_f.close();

    // unique flows size (sample, without sample)
    double total_unique_flow_size=0, sampled_unique_flow_size=0, total_unique_ip=0;
    for(map<string, map<string, int>>::iterator i=unique_flows.begin(); i!=unique_flows.end(); i++)
    {
        total_unique_flow_size+=i->second.size();
    }
    for(map<string, map<string, int>>::iterator i=sampled_unique_flows.begin(); i!=sampled_unique_flows.end(); i++)
    {
        sampled_unique_flow_size+=i->second.size();
    }
    for(map<string, int>::iterator i=unique_IP.begin(); i!=unique_IP.end(); i++)
    {
        total_unique_ip++;
    }
    cout << "=====================================================" << endl;
    cout << "Total unique IP: " << total_unique_ip << endl;
    cout << "Total unique flow size: " << total_unique_flow_size << endl;
    cout << "Sampled unique flow size: " << sampled_unique_flow_size << endl;
    cout << "Sampled unique flow size: " << sampled_unique_flow_size/(float)total_unique_flow_size << endl;

    cout << "=====================================================" << endl;
    cout << "Threshold: " << endl;
    cout << "Module 1: " << threshold_1 << endl;
    cout << "Module 2: " << threshold_2 << endl;
    cout << "Module 3: " << threshold_3 << endl;
    cout << "Module 4: " << threshold_4 << endl;
    cout << "Module 5: " << threshold_5 << endl;
    cout << "=====================================================" << endl;

    cout << "Table size: " << table_size << endl;
    cout << "Collision rate: " << collision/(float)total_pkt << endl;       // using total_pkt instead of total, calculate entire collision rate
    cout << "Sampled ratio: " << sampled_pkt/(float)total_pkt << endl;
    cout << "Sampled anomaly ratio (sampled_anomaly/total): " << sampled_anomaly_pkt/(float)total_pkt << endl;
    cout << "Sampled anomaly ratio (sampled_anomaly/total_anomaly): " << sampled_anomaly_pkt/(float)anomaly_pkt << endl;
    cout << "Anomaly ratio: " << anomaly_pkt/(float)total_pkt << endl;
    cout << "Sampled anomaly ratio (total): " << sampled_anomaly_pkt/(float)total_pkt << endl;
    cout << "Seperated timeout (sec): " << seperated_timeout << endl;
    cout << "Long-term timeout (sec): " << long_term_timeout << endl;
    cout << "Report Message (without/with mitigation): " << report_cnt << "/" << report_with_mitigation_cnt << ". Reduced " << (report_cnt-report_with_mitigation_cnt)*100/(float)report_cnt << "% of total messages." << endl; 
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

    total_pkt++;

    // Parse IPv4
    if(ethernet->etherType == (u_short)8){
        ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
        u_int size_ip = IP_HL(ipv4)*4;
        size_existed += size_ip;

        // Step1: Get flow id
        string srcIP = string(inet_ntoa(ipv4->srcAddr));
        string dstIP = string(inet_ntoa(ipv4->dstAddr));

        // store unique flows
        unique_flows[srcIP][dstIP]=1;
        // store unique IP
        unique_IP[srcIP]=1;
        unique_IP[dstIP]=1;

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
        
        if( (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), srcIP) != anomaly_IP_list.end()) &&
            (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), dstIP) != anomaly_IP_list.end())
            ) {
                anomaly_pkt++;
            }

        // if interval > 100ms (flowlet), detect

        if(interval > long_term_timeout ) {
            // > 10 sec, reset 
            mod1[flowIndex]=0;
            mod4_diffcnt[flowIndex]=0;
            mod5[flowIndex]=0;
            repo_bitmap[flowIndex]=0;

            c_srcIP[flowIndex]=string("null");
            c_dstIP[flowIndex]=string("null");
        }
        
        if(interval > seperated_timeout && (lastseen_ts!=0)){
            
            if( (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), srcIP) == anomaly_IP_list.end()) &&
                (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), dstIP) == anomaly_IP_list.end())
                ) {
                    benign_burst_len_mod1[mod1[flowIndex]]++;
                    benign_burst_len_seq.push_back(mod1[flowIndex]);
                }
            // record
            if( (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), srcIP) != anomaly_IP_list.end()) &&
                (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), dstIP) != anomaly_IP_list.end())
                ) {
                    anomaly_burst_len_mod1[mod1[flowIndex]]++;
                    anomaly_burst_len_seq.push_back(mod1[flowIndex]);
                }
            // sampled_unique_flows[srcIP][dstIP]=1;
            // compare to threshold (configurable)
            if(mod1[flowIndex]>threshold_1){
                // high frequency 
                repo_bitmap_val|=1;


                // goto mod5
                if( mod5[flowIndex] >= threshold_5 ){
                    // report
                    repo_bitmap_val |= 16;
                    mod5[flowIndex]=0;
                    
                    anomaly_burst_len_when_trigger_detect[mod1[flowIndex]]++;
                }

                // goto mod4
                if(mod4_diffcnt[flowIndex] >= threshold_4){
                    // report
                    repo_bitmap_val |= 8;
                    mod4_diffcnt[flowIndex]=0;

                    anomaly_burst_len_when_trigger_detect[mod1[flowIndex]]++;
                }

            } else {
                // low frequency
                // goto mod4
                if(mod4_diffcnt[flowIndex] >= threshold_4){
                    // report
                    repo_bitmap_val |= 8;
                    mod4_diffcnt[flowIndex]=0;

                    anomaly_burst_len_when_trigger_detect[mod1[flowIndex]]++;
                }
            }

            // reset the state 
            mod1[flowIndex]=1;

            // collision checker
            /*if(c_srcIP[flowIndex]=="null"|| c_dstIP[flowIndex]=="null"){
                // do nothing, initialize state
            }
            else if(c_srcIP[flowIndex]!=srcIP || c_dstIP[flowIndex]!=dstIP){
                collision++;
            } 
            total++;
            // update
            c_srcIP[flowIndex]=srcIP;
            c_dstIP[flowIndex]=dstIP;*/
        } else {
            sampled_pkt++;
            
            sampled_unique_flows[srcIP][dstIP]=1;

            // collision checker
            if(c_srcIP[flowIndex]==string("null")|| c_dstIP[flowIndex]==string("null")){
                // do nothing, initialize state
            }
            else if(c_srcIP[flowIndex]!=srcIP || c_dstIP[flowIndex]!=dstIP){
                collision++;
            } 
            total++;
            // update
            c_srcIP[flowIndex]=srcIP;
            c_dstIP[flowIndex]=dstIP;

            // update mod1
            mod1[flowIndex]++;
            // update mod4
            if(prev_dport[flowIndex] != dstPort){
                mod4_diffcnt[flowIndex]++;
            }
            prev_dport[flowIndex]=dstPort;

            // update mod5
            if(tcp!=NULL){
                if(tcp->flags&TH_RST){
                    // RST
                    mod5[flowIndex]++;
                }
            }

            if( (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), srcIP) != anomaly_IP_list.end()) &&
                (find(anomaly_IP_list.begin(), anomaly_IP_list.end(), dstIP) != anomaly_IP_list.end())
                ) {
                    sampled_anomaly_pkt++;
                }
        }

        // check report_bitmap value
        if(repo_bitmap_val>1){
            report_cnt++;
            if((repo_bitmap_val|repo_bitmap[flowIndex])!=repo_bitmap[flowIndex]){
                // report, and record 
                // cout << srcIP << "->" << dstIP << ". Report_bitmap: " << repo_bitmap_val << ". Value: " << mod1[flowIndex] << ", " << mod4_diffcnt[flowIndex] << ", " << mod5[flowIndex] << endl;

                report_pairs_t report;
                report.srcIP=srcIP;
                report.dstIP=dstIP;
                report.type=repo_bitmap_val;
                report_pairs.push_back(report);

                // inc
                report_with_mitigation_cnt++;
            }
            repo_bitmap[flowIndex]|=repo_bitmap_val;
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