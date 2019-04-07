/**
 * Find out port distribution of each flow.
 * 
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
    map<int, int> port_record;  // | port number | counter value |
    int recv_pktcnt;
    int sent_pktcnt;
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
                        // dst
                        pktstat[string(inet_ntoa(ipv4->dstAddr))].port_record[tcp->dport]++;
                        pktstat[string(inet_ntoa(ipv4->dstAddr))].recv_pktcnt++;
                        // src
                        pktstat[string(inet_ntoa(ipv4->srcAddr))].port_record[tcp->sport]++;
                        pktstat[string(inet_ntoa(ipv4->srcAddr))].sent_pktcnt++;

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

    double total_uniq_port_cnt=0.0, std_uniq_port_cnt=0.0, mean_uniq_port_cnt=0.0;
    int cnt=0;
    for(map<string, flow_t>::iterator iter=pktstat.begin();
        iter!=pktstat.end(); ++iter)
    {
        int uniq_port_per_flow=0;
        //cout << "IP: " << iter->first << endl;
        for(map<int, int>::iterator i=iter->second.port_record.begin();
            i!=iter->second.port_record.end(); ++i)
        {
            // i->first: port number
            // i->second: counter value
            uniq_port_per_flow+=i->second;
        }
        //cout << "Unique ports: " << uniq_port_per_flow << endl;
        // increment
        total_uniq_port_cnt+=uniq_port_per_flow;
        std_uniq_port_cnt+=pow(uniq_port_per_flow, 2);
        cnt++;
    }

    // Avg
    cout << "Avg. uniq port per flow: " << total_uniq_port_cnt/cnt << endl;
    mean_uniq_port_cnt = total_uniq_port_cnt/cnt;
    // Std
    cout << "Std. uniq port per flow: " << sqrt(std_uniq_port_cnt/cnt - pow(total_uniq_port_cnt/cnt, 2)) << endl;
    std_uniq_port_cnt = sqrt(std_uniq_port_cnt/cnt - pow(total_uniq_port_cnt/cnt, 2));

    for(map<string, flow_t>::iterator iter=pktstat.begin();
        iter!=pktstat.end(); ++iter)
    {
        int uniq_port_per_flow=0;
        
        for(map<int, int>::iterator i=iter->second.port_record.begin();
            i!=iter->second.port_record.end(); ++i)
        {
            // i->first: port number
            // i->second: counter value
            uniq_port_per_flow+=i->second;
        }
        if(uniq_port_per_flow > mean_uniq_port_cnt+std_uniq_port_cnt){
            cout << "IP: " << iter->first << endl;
            cout << "Unique ports: " << uniq_port_per_flow << endl;
        }
    }

    return 0;
}