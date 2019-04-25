/**
 * Using Bitmap to control/report.
 * 
 * Bitmap usage explanation:
 *  - Base on the control bitmap to decide which module should be executed.
 *  - And each module will report to same report bitmap (corresponding to each bit), and if necessary will change the control bitmap.
 * (incoming packet) -> | control bitmap | -> ... (module which flag with 1) -> | report bitmap | 
 * 
 * Module sequence:
 *  - Base on the dependencies between each features. For example, sent/recv ratio come after amount/frequency of packets.
 *  - And MSB (Most significant bit) will be denoted as high priority.
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

extern "C"
{
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
u_int size_ip, size_tcp, size_udp, size_icmp, size_existed=0;

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
map<string, map<string, int>> mod1;             // module 1 - frequency and amount of packets
map<string, map<string, int>> mod2;             // module 2 - sent/recv ratio
map<string, map<string, int>> mod3;             // module 3 - TCP control flags (SYN vs ACK)
map<string, map<string, int>> mod4;             // module 4 - ICMP error control 

vector<int> amount_count;

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

        while(packet=pcap_next(handle, &header)){
            ethernet = (struct sniff_ethernet*)(packet);
            size_existed += SIZE_ETHER;

            /* ============================================= */
            /* Ethernet  */
            /* ============================================= */

            // Parse IPv4
            if(ethernet->etherType == (u_short)8){
                ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
                size_ip = IP_HL(ipv4)*4;
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

                // Step2: Get the execute bitmap for this entry
                // exec_bitmap_val=(exec_bitmap.find(srcIP).find(dstIP)==exec_bitmap.find(srcIP).end()? 1 : exec_bitmap[srcIP][dstIP]);
                if(exec_bitmap[srcIP].find(dstIP)==exec_bitmap[srcIP].end()){
                    // exec_bitmap[srcIP][dstIP]=1;
                    exec_bitmap_val=1;
                } else {
                    exec_bitmap_val=exec_bitmap[srcIP][dstIP];
                }
                // rev_exec_bitmap_val=(exec_bitmap.find(rev_flowIndex)==exec_bitmap.end()? 1 : exec_bitmap[rev_flowIndex]);

                /* ============================================= */
                /* IPv4             */
                /* ============================================= */

                // Step3: execute each module defined by bitmap - get lastSeen 
                double lastseen_ts, interval=0, rev_lastseen_ts, rev_interval=0;
                // ts
                // lastseen_ts=(lastSeen.find(srcIP).find(dstIP)==lastSeen.find(srcIP).end()? 0 : lastSeen[srcIP][dstIP]);
                if(lastSeen[srcIP].find(dstIP)==lastSeen[srcIP].end()){
                    //lastSeen[srcIP][dstIP]=0;
                    lastseen_ts = 0;
                } else {
                    lastseen_ts=lastSeen[srcIP][dstIP];
                }
                // rev_lastseen_ts=(lastSeen.find(rev_flowIndex)==lastSeen.end()? 0 : lastSeen[rev_flowIndex]);
                // interval
                interval = (header.ts.tv_sec + header.ts.tv_usec/1000.0) - lastseen_ts;
                // rev_interval = (header.ts.tv_sec + header.ts.tv_usec/1000.0) - rev_lastseen_ts;
                
                // if lastseen_ts==0, then no need to do the detection, just update the module

                // Mod1: get amount/frequency of packets
                if((exec_bitmap_val&1)){
                    // if interval > 100ms (flowlet), detect
                    if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                        // read from mod1
                        int pktcnt=mod1[srcIP][dstIP]+1;
                        int rev_pktcnt=mod1[dstIP][srcIP]+1;
                        // compare to threshold (configurable)
                        if(pktcnt>100){
                            // debug: print out the src,dst IP pair
                            //cout << "Amount and Frequency surpass!" << endl;
                            //cout << string(inet_ntoa(ipv4->srcAddr)) << "-> " << string(inet_ntoa(ipv4->dstAddr)) << endl;
                            
                            // report to repo_bitmap
                            /*if(repo_bitmap.find(srcIP)==repo_bitmap.end()){
                                repo_bitmap[flowIndex]=0x1;
                            } else {
                                repo_bitmap[flowIndex]=(repo_bitmap[flowIndex] | 0x1);
                            }*/
                            repo_bitmap[srcIP][dstIP]|=1;
                            // FIXME: decide to update exec_bitmap or not (adaptive/optional)
                            exec_bitmap[srcIP][dstIP]|=2;
                        } else if(rev_pktcnt>100){
                            repo_bitmap[dstIP][srcIP]|=1;
                            exec_bitmap[dstIP][srcIP]|=2;
                        }
                        amount_count.push_back(pktcnt);
                        
                        // reset the state 
                        mod1[srcIP][dstIP]=0;
                        mod1[dstIP][srcIP]=0;
                    } else {
                        // update mod1
                        if(mod1[srcIP].find(dstIP)==mod1[srcIP].end()){
                            mod1[srcIP][dstIP]=1;
                        } else {
                            mod1[srcIP][dstIP]++;
                        }

                        // update rev 
                        if(mod1[dstIP].find(srcIP)==mod1[dstIP].end()){
                            mod1[dstIP][srcIP]=1;
                        } else {
                            mod1[dstIP][srcIP]++;
                        }
                    }

                }

                // Mod2: unbalanced sent/recv packets
                if((exec_bitmap_val&2)){
                    // if interval > 100ms, detect
                    if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                        // get the sent and recv pkt ratio
                        int sent=mod2[srcIP][dstIP];
                        int recv=mod2[dstIP][srcIP];
                        // calculate sent/recv ratio
                        if((sent/(float)recv) < (2/9.0)){
                            // victim 
                            //cout << "[Victim] Sent/Recv ratio: " << sent/(float)recv << endl;
                            //cout << string(inet_ntoa(ipv4->srcAddr)) << "-> " << string(inet_ntoa(ipv4->dstAddr)) << endl; 
                            // report to repo_bitmap
                            // direct
                            if(repo_bitmap[srcIP].find(dstIP)==repo_bitmap[srcIP].end()){
                                repo_bitmap[srcIP][dstIP]=2;
                            } else {
                                repo_bitmap[srcIP][dstIP]|=2;
                            }
                            // reverse
                            if(repo_bitmap[dstIP].find(srcIP)==repo_bitmap[dstIP].end()){
                                repo_bitmap[dstIP][srcIP]=2;
                            } else {
                                repo_bitmap[dstIP][srcIP]|=2;
                            }

                            // update execute bitmap (if victim, then go to 0x4)
                            exec_bitmap[srcIP][dstIP]|=4;
                        } 
                        if((sent/(float)recv) > (9.0/2.0)){
                            // attacker 
                            //cout << "[Attacker] Sent/Recv ratio: " << sent/(float)recv << endl;
                            //cout << string(inet_ntoa(ipv4->srcAddr)) << "-> " << string(inet_ntoa(ipv4->dstAddr)) << endl; 
                            // report to repo_bitmap 
                            // FIXME: need different bit to represent "victim" or "attacker"?
                            // direct 
                            if(repo_bitmap[srcIP].find(dstIP)==repo_bitmap[srcIP].end()){
                                repo_bitmap[srcIP][dstIP]=2;
                            } else {
                                repo_bitmap[srcIP][dstIP]|=2;
                            } 
                            // reverse
                            if(repo_bitmap[dstIP].find(srcIP)==repo_bitmap[dstIP].end()){
                                repo_bitmap[dstIP][srcIP]=2;
                            } else {
                                repo_bitmap[dstIP][srcIP]|=2;
                            }

                            // update execute bitmap (if attacker, then go to 0x8)
                            exec_bitmap[srcIP][dstIP]|=8;
                        }

                        // reset the state
                        //mod2[srcIP][dstIP]=0;
                        //mod2[dstIP][srcIP]=0;
                    } else {
                        // update mod2 (only need to update one direction - sent)
                        if(mod2[srcIP].find(dstIP)==mod2[srcIP].end()){
                            mod2[srcIP][dstIP]=1;
                        } else {
                            mod2[srcIP][dstIP]++;
                        }
                    }
                }

                if(size_ip < 20){
                    printf("Invalid IPv4 header length: %u bytes\n", size_ip);
                } else {
                    // Parse TCP 
                    if(ipv4->protocol == (u_char)6){
                        tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                        size_tcp = TH_OFF(tcp)*4;
                        size_existed += size_tcp;
                        /* ============================================= */
                        /* TCP              */
                        /* ============================================= */

                        // Mod3: TCP stats, SYN > ACK 
                        // Mechanism: SYN++, ACK--
                        // debug=> ||1 => must enter this 
                        /*if((exec_bitmap_val&0x4)||1){
                            // if interval > 100ms, detect
                            if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                                int flowval=0;
                                if(tcp->flags&TH_SYN){
                                    flowval=mod3[flowIndex]+1;
                                } else if(tcp->flags&TH_ACK){
                                    flowval=mod3[flowIndex]--;
                                }
                                
                                // compare threshold
                                if(flowval > 100){
                                    // SYN > 100 (Lots of SYN)
                                    // represent (Attacker to Victim)
                                    if(repo_bitmap.find(flowIndex)==repo_bitmap.end()){
                                        repo_bitmap[flowIndex]=0x4;
                                    } else {
                                        repo_bitmap[flowIndex]=(repo_bitmap[flowIndex] | 0x4);
                                    }
                                } 

                                // reset
                                mod3[flowIndex]=0;

                            } else {
                                // update
                                if(mod3.find(flowIndex)==mod3.end()){
                                    if(tcp->flags&TH_SYN){
                                        mod3[flowIndex]=1;
                                    } else if(tcp->flags&TH_ACK){
                                        mod3[flowIndex]=-1;
                                    }
                                } else {
                                    if(tcp->flags&TH_SYN){
                                        mod3[flowIndex]++;
                                    } else if(tcp->flags&TH_ACK){
                                        mod3[flowIndex]--;
                                    }
                                }
                            }
                        }*/

                    } else if(ipv4->protocol == (u_char)17){
                        udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                        size_udp = 8; // 8 bytes
                        size_existed += size_udp;

                        /* ============================================= */
                        /* UDP              */
                        /* ============================================= */
                    } else if(ipv4->protocol == (u_char)1){
                        /* ============================================= */
                        /* ICMP              */
                        /* ============================================= */
                        icmp = (struct sniff_icmp*)(packet + SIZE_ETHER + size_ip);
                        size_icmp = 4; // 4 bytes
                        size_existed += size_icmp;

                        // TODO:
                        // Extra module: check for icmp code number
                        // e.g. If there existed UDP flood attack, there will have lots of ICMP message,
                        // which has code represent "Unreachable".

                        // debug (execute directly)
                        /*if((exec_bitmap_val&0x8)||1){
                            // if interval > 100ms , detect
                            if(interval > FLOWLET_TIMEOUT && (lastseen_ts!=0)){
                                int flowval=0;
                                // category: target unreachable
                                if(icmp->type==3||icmp->type==11||icmp->type==12){
                                    flowval=mod4[flowIndex]+1;
                                } else {
                                    // FIXME: 
                                    // simply set the other flags as nothing 
                                    flowval=mod4[flowIndex]-1;
                                }

                                // detect with threshold
                                if(flowval>=5){
                                    // sequential ICMP target unreachable

                                    // report
                                    if(repo_bitmap.find(flowIndex)==repo_bitmap.end()){
                                        repo_bitmap[flowIndex]=0x8;
                                    } else {
                                        repo_bitmap[flowIndex]=(repo_bitmap[flowIndex] | 0x8);
                                    }
                                }

                                // reset 
                                mod4[flowIndex]=0;

                            } else {
                                // update 
                                if(mod4.find(flowIndex)==mod4.end()){
                                    if(icmp->type==3||icmp->type==11||icmp->type==12){
                                        mod4[flowIndex]=1;
                                    } else {
                                        mod4[flowIndex]=0;
                                    }
                                } else {
                                    if(icmp->type==3||icmp->type==11||icmp->type==12){
                                        mod4[flowIndex]++;
                                    } else {
                                        mod4[flowIndex]--;
                                    }
                                }
                            }
                        }*/
                    }
                }

                /* ============================================= */
                /* Others (L3)  */
                /* ============================================= */

                // check report_bitmap value
                if(repo_bitmap[srcIP][dstIP]>=1){
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
                }

                // update lastseen (Need to wait until all module has been finished)
                lastSeen[srcIP][dstIP]=(header.ts.tv_sec + header.ts.tv_usec/1000.0);
            }
            /* ============================================= */
            /* Others (L2)  */
            /* ============================================= */


            payload = (char*)(packet + size_existed);
            size_existed = 0; // reset
        }
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