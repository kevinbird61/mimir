/**
 * Statistics of TCP flags.
 * 
 * | IP | score |
 * 
 * 利用 score function，當 packet 中出現 SYN 時，對 [srcIP] 欄位 +1 
 * 而出現 RST 時，對 [srcIP] 欄位 -1 （這時的 srcIP 很有可能為 victim，而 dstIP 則是 botnet 其中一員）
 * 
 * Botnet 中所使用的 ip 通常是非法的，所以應該沒有紀錄需求（在前面假設成立）
 * 所以我們可以藉由 RST 數量來得知，該接收端是在收到大量偽造封包下（且沒有送 SYN 請求連線的情況下），造成回應大量的 RST。
 * 而在這樣的行為下，若 SYN 數量不足的情況下，數值會特別小 （負很大）
 *  
 * 
 * 另外也可以計算 "Sent" 與 "Received" 之間數量比例作為判斷依據。
 * 並嘗試比較利用 TCP 機制與這樣的發送比，哪種所得到的訊息較為精準。
 * 
 * | IP | # of "Sent" packets | # of "Received" packets |
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

// stateful variables
typedef struct __pktcnt {
    // statistics for tcp
    int rst;
    int ack;
    int syn;
    int fin;
    // # of packets
    int sent;
    int recv;
} pktcnt_t;

map<string, pktcnt_t> pkt_stats;

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

            // Parse IPv4
            if(ethernet->etherType == (u_short)8){
                ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
                size_ip = IP_HL(ipv4)*4;
                size_existed += size_ip;

                // pkt_stats
                pkt_stats[string(inet_ntoa(ipv4->srcAddr))].sent++;
                pkt_stats[string(inet_ntoa(ipv4->dstAddr))].recv++;

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

                        // Compute score
                        if(tcp->flags > 0){
                            if(((tcp->flags&TH_SYN))){
                                // Only SYN, +1
                                pkt_stats[string(inet_ntoa(ipv4->srcAddr))].syn+=1;
                            }
                            if(((tcp->flags&TH_ACK))){
                                // Only SYN, +1
                                pkt_stats[string(inet_ntoa(ipv4->srcAddr))].ack+=1;
                            }
                            if(((tcp->flags&TH_RST))){
                                // RST, -1
                                pkt_stats[string(inet_ntoa(ipv4->srcAddr))].rst+=1;
                            }
                            if(((tcp->flags&TH_FIN))){
                                // RST, -1
                                pkt_stats[string(inet_ntoa(ipv4->srcAddr))].fin+=1;
                            }
                        }
                    } 
                }

            }

            // Rest part
            payload = (char*)(packet + size_existed);
            size_existed = 0; // reset
        }
    }

    // statistical variables
    // mean, standard deviation
    float sent_mean=0.0, sent_std=0.0, recv_mean=0.0, recv_std=0.0, cnt=0.0;

    // Print out statistics
    for(map<string, pktcnt_t>::iterator iter=pkt_stats.begin();
        iter!=pkt_stats.end(); ++iter)
    {
        //cout << "IP: " << iter->first << endl;
        //cout << "scoring: " << iter->second.scoring << endl;
        //cout << "# of packets (Sent): " << iter->second.sent << endl;
        //cout << "# of packets (Recv): " << iter->second.recv << endl;
        // sum
        sent_mean+=iter->second.sent;
        recv_mean+=iter->second.recv;
        sent_std+=pow(iter->second.sent, 2);
        recv_std+=pow(iter->second.recv, 2);
        cnt++;
    }

    // cal
    sent_std = sqrt(sent_std/cnt - pow(sent_mean/cnt, 2));
    sent_mean = sent_mean/cnt;
    recv_std = sqrt(recv_std/cnt - pow(recv_mean/cnt, 2));
    recv_mean = recv_mean/cnt;

    for(map<string, pktcnt_t>::iterator iter=pkt_stats.begin();
        iter!=pkt_stats.end(); ++iter)
    {
        if(iter->second.sent >= (sent_mean + 3*sent_std)){
            
            if(iter->second.sent !=0 && iter->second.recv != 0){ 
                if((float)iter->second.sent/iter->second.recv > 2.5){
                    cout << "Attacker Confirmed." << endl;
                    cout << "[Attacker Candidate] IP: " << iter->first << endl;
                    cout << "# of packets sent: " << iter->second.sent << endl;
                    cout << "# of packets recv: " << iter->second.recv << endl;
                    cout << "Ratio of packets (Sent/Recv): " << (float)iter->second.sent/iter->second.recv << endl; 
                    // Print tcp statistics (Suppose to be another filter)
                    cout << "# of SYN: " << iter->second.syn << endl;
                    cout << "# of ACK: " << iter->second.ack << endl;
                    cout << "# of RST: " << iter->second.rst << endl; 
                    cout << "# of FIN: " << iter->second.fin << endl; 
                }
            }
        }
        if(iter->second.recv >= (recv_mean + 3*recv_std)){
            
            // cout << "Ratio of packets (Recv/Sent): " << iter->second.recv/iter->second.sent << endl;
            if(iter->second.sent !=0 && iter->second.recv != 0){
                if((float)iter->second.recv/iter->second.sent > 2.5){
                    cout << "Victim Confirmed." << endl;
                    cout << "[Victim Candidate] IP: " << iter->first << endl;
                    cout << "# of packets sent: " << iter->second.sent << endl;
                    cout << "# of packets recv: " << iter->second.recv << endl;
                    cout << "Ratio of packets (Recv/Sent): " << (float)iter->second.recv/iter->second.sent << endl;  
                    // Print tcp statistics (Suppose to be another filter)
                    cout << "# of SYN: " << iter->second.syn << endl;
                    cout << "# of ACK: " << iter->second.ack << endl;
                    cout << "# of RST: " << iter->second.rst << endl; 
                    cout << "# of FIN: " << iter->second.fin << endl; 
                }
            }
        }
    }

    return 0;
}