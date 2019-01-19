#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <math.h>

#include "lib/packet_def.h"
#include "lib/hash.h"
#include "lib/hamming.h"

#include "hash/xxhash.h"
#include "cmap/map.h"

// hash table size 
#define TABLE_SLOT 512
// N-record limitation
#define LIMIT_NUM 10
// ethernet 
#define SIZE_ETHER 14

const struct sniff_ethernet *ethernet; // ethernet header
const struct sniff_ipv4 *ipv4; // IPv4 header
const struct sniff_tcp *tcp;   // TCP header
const struct sniff_udp *udp;   // UDP header
const char *payload; // packet payload
u_int size_ip, size_tcp, size_udp, size_existed=0;

// data structure of evaluation
typedef struct _eva {
    uint32_t port_id;
    uint32_t diffcnt;   // number of difference
    uint32_t hamming;   // hamming distance
} eva_t;

struct _record_elem {
    uint32_t port_id;       // current index (the feature we want to monitor. e.g. port id)
    // bi-direction linked-list
    struct _record_elem *next;
    struct _record_elem *prev;  
};

// data structure of N-records
typedef struct _n_records {
    uint8_t num_record;         // number of existed record (linked-list)
    float   entropy;
    uint32_t ma;
    // uint32_t srcAddr;
    // uint32_t dstAddr;
    struct  _record_elem *ptr;   // header pointer of N records
} record_t;

// report ip (diffcnt)
map_int_t ipv4_src_addr;
map_int_t ipv4_dst_addr;
// report ip (hamming)
map_int_t ipv4_src_addr_h;
map_int_t ipv4_dst_addr_h;
// report ip (N-records)
map_int_t ipv4_src_addr_n_d;
map_int_t ipv4_src_addr_n_h;


// Key-Value pair 
eva_t tcp_tb[TABLE_SLOT]={0};
eva_t udp_tb[TABLE_SLOT]={0};

// N-records table 
record_t n_tcp_rd[TABLE_SLOT]={0};
record_t n_udp_rd[TABLE_SLOT]={0};

// map inc 
void map_inc(map_int_t *m, void *key){
    int *ori = map_get(m, key);
    if(ori){
        map_set(m, key, (*ori)+1 );
    } else {
        map_set(m, key, 1);
    }
}

int main(int argc, char **argv) 
{ 
    unsigned int flow_id;
    struct pcap_pkthdr header; 
    const u_char *packet;
    if (argc < 2) { 
        fprintf(stderr, "Usage: %s <pcap>\n", argv[0]); 
        exit(1); 
    } 
    pcap_t *handle; 
    char errbuf[PCAP_ERRBUF_SIZE];  
    handle = pcap_open_offline(argv[1], errbuf); 
    if (handle == NULL) { 
        fprintf(stderr, "Couldn't open pcap file: %s\n", argv[1]); 
        fprintf(stderr, "%s\n", errbuf);
        return(2); 
    } 

    // eva 
    map_init(&ipv4_src_addr);
    map_init(&ipv4_dst_addr);
    map_init(&ipv4_src_addr_h);
    map_init(&ipv4_dst_addr_h);
    // n-records
    map_init(&ipv4_src_addr_n_d);
    map_init(&ipv4_src_addr_n_h);

    // Get each packet from pcap file
    while (packet = pcap_next(handle,&header)) {
        // printf("%d\n", header.len);
        /* Packet parsing process */
        ethernet = (struct sniff_ethernet*)(packet);
        size_existed += SIZE_ETHER;

        // Parse IPv4
        if(ethernet->etherType == (u_short)8){
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
            size_ip = IP_HL(ipv4)*4;
            size_existed += size_ip;

            if(size_ip < 20){
                printf("Invalid IPv4 header length: %u bytes\n", size_ip);
            } else {
                unsigned char IP[8]={0};
                *IP = ipv4->srcAddr.s_addr;
                *(IP+4) = ipv4->dstAddr.s_addr;
                // get flow id
                flow_id = crc16(IP, 8) % TABLE_SLOT;
            }
            // Parse TCP 
            if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;

                if(size_tcp < 20){
                    printf("Invalid TCP header length: %u bytes\n", size_tcp);
                } else {
                    unsigned char Port[4]={0};
                    *Port = tcp->sport;
                    *(Port+2) = tcp->dport;
                    // get port id
                    unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                    // cal 
                    if(tcp_tb[flow_id].port_id != index){
                        tcp_tb[flow_id].hamming += popcount32_better(tcp_tb[flow_id].port_id ^ index); // get hamming 
                        tcp_tb[flow_id].port_id = index; // update
                        tcp_tb[flow_id].diffcnt++;
                    }
                    /* N-record part */
                    // push into N-record 
                    /*
                    if(n_tcp_rd[flow_id].num_record == 0){
                        struct _record_elem *new_elem = (struct _record_elem*)malloc(sizeof(struct _record_elem));
                        new_elem->port_id = index;
                        new_elem->next = NULL;
                        new_elem->prev = NULL;
                        n_tcp_rd[flow_id].ptr = new_elem;
                        n_tcp_rd[flow_id].num_record=1;
                    } else {
                        struct _record_elem *elem_ptr;
                        elem_ptr = n_tcp_rd[flow_id].ptr;
                        int recordNum=0, S=0;
                        uint32_t diffCntQ[LIMIT_NUM], hammWQ[LIMIT_NUM];
                        uint32_t diffCnt=0,hammingW=0;
                        float entropyVal_d=0.0, entropyVal_h=0.0, ma_d=0.0, ma_h=0.0;
                        uint32_t popout;
                        while(elem_ptr!=NULL){
                            recordNum++;
                            // get diff & hamming
                            if(index != elem_ptr->port_id) {
                                diffCnt++;
                                diffCntQ[S] = 1;
                                hammingW += popcount32_fast_mul(index ^ elem_ptr->port_id);
                                hammWQ[S] = popcount32_fast_mul(index ^ elem_ptr->port_id);
                                S++;
                            }
                            // popout (push new record into history), replace
                            popout = elem_ptr->port_id;
                            elem_ptr->port_id = index;
                            // shift to next
                            elem_ptr = elem_ptr->next;
                        }
                        // if surpass LIMIT_NUM, then we dont create
                        // new node for it.
                        if(recordNum < LIMIT_NUM){
                            // create new node for it 
                            struct _record_elem *newnode = (struct _record_elem*)malloc(sizeof(struct _record_elem));
                            newnode->port_id = popout;
                            // link to elem_ptr
                            elem_ptr = newnode;
                            newnode->next = NULL;
                            newnode->prev = NULL;
                            // newnode->prev = elem_ptr;
                            n_tcp_rd[flow_id].num_record = recordNum+1;
                        } else {
                            // just discard popout
                        }
                        // calculate entropy
                        for(uint32_t i=0; i<S; i++){
                            // entropyVal_d += (diffCntQ[i]/(float)recordNum)*(log2f(diffCntQ[i]/(float)recordNum));
                            entropyVal_h += (hammWQ[i]/(float)recordNum)*(log2f(hammWQ[i]/(float)recordNum));
                        }

                        // assign diff & hamming into target OD pair
                        n_tcp_rd[flow_id].entropy = entropyVal_h;
                        n_tcp_rd[flow_id].ma = hammingW/recordNum;
                        // 
                        map_set(&ipv4_src_addr_n_d, inet_ntoa(ipv4->srcAddr), diffCnt/recordNum);
                        // map_set(&ipv4_src_addr_n_h, inet_ntoa(ipv4->srcAddr), hammingW/recordNum);
                        // map_set(&ipv4_src_addr_n_d, inet_ntoa(ipv4->srcAddr), entropyVal_d);
                        map_set(&ipv4_src_addr_n_h, inet_ntoa(ipv4->srcAddr), entropyVal_h);
                    }*/
                }
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                size_udp = 8; // 8 bytes
                size_existed += size_udp;

                unsigned char Port[4]={0};
                *Port = udp->sport;
                *(Port+2) = udp->dport;
                // get port id
                unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                // cal 
                if(udp_tb[flow_id].port_id != index){
                    udp_tb[flow_id].hamming += popcount32_better(udp_tb[flow_id].port_id ^ index); // get hamming 
                    udp_tb[flow_id].port_id = index; // update
                    udp_tb[flow_id].diffcnt++;
                }
            }
        }
        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset
    } 
    pcap_close(handle);

    uint32_t tdiff=0, udiff=0, thamm=0, uhamm=0;
    for(int i=0;i<TABLE_SLOT;i++){
        // normal way
        tdiff += tcp_tb[i].diffcnt;
        udiff += udp_tb[i].diffcnt;
        thamm += tcp_tb[i].hamming;
        uhamm += udp_tb[i].hamming;
    }

    printf("Mean TCP diff. count: %.2f\n", (float)tdiff/TABLE_SLOT);
    printf("Mean UDP diff. count: %.2f\n", (float)udiff/TABLE_SLOT);
    printf("Mean TCP hamming distance: %.2f\n", (float)thamm/TABLE_SLOT);
    printf("Mean UDP hamming distance: %.2f\n", (float)uhamm/TABLE_SLOT);

    float tdvar=0.0, udvar=0.0, thvar=0.0, uhvar=0.0;
    for(int i=0;i<TABLE_SLOT;i++){
        tdvar += pow(tcp_tb[i].diffcnt - (float)tdiff/TABLE_SLOT, 2);
        udvar += pow(udp_tb[i].diffcnt - (float)udiff/TABLE_SLOT, 2);
        thvar += pow(tcp_tb[i].hamming - (float)thamm/TABLE_SLOT, 2);
        uhvar += pow(udp_tb[i].hamming - (float)uhamm/TABLE_SLOT, 2);

        // clear 
        tcp_tb[i].diffcnt = 0;
        tcp_tb[i].hamming = 0;
        udp_tb[i].diffcnt = 0;
        udp_tb[i].hamming = 0;
    }

    printf("Var TCP diff. count: %.2f\n", sqrt(tdvar/TABLE_SLOT));
    printf("Var UDP diff. count: %.2f\n", sqrt(udvar/TABLE_SLOT));
    printf("Var TCP hamming distance: %.2f\n", sqrt(thvar/TABLE_SLOT));
    printf("Var UDP hamming distance: %.2f\n", sqrt(uhvar/TABLE_SLOT));


    // Compare with the threshold
    handle = pcap_open_offline(argv[1], errbuf);  // reload 
    while (packet = pcap_next(handle,&header)) {
        // printf("%d\n", header.len);
        /* Packet parsing process */
        ethernet = (struct sniff_ethernet*)(packet);
        size_existed += SIZE_ETHER;

        // Parse IPv4
        if(ethernet->etherType == (u_short)8){
            ipv4 = (struct sniff_ipv4*)(packet + SIZE_ETHER);
            size_ip = IP_HL(ipv4)*4;
            size_existed += size_ip;

            if(size_ip < 20){
                printf("Invalid IPv4 header length: %u bytes\n", size_ip);
            } else {
                unsigned char IP[8]={0};
                *IP = ipv4->srcAddr.s_addr;
                *(IP+4) = ipv4->dstAddr.s_addr;
                // get flow id
                flow_id = crc16(IP, 8) % TABLE_SLOT;
            }
            // Parse TCP 
            if(ipv4->protocol == (u_char)6){
                tcp = (struct sniff_tcp*)(packet + SIZE_ETHER + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                size_existed += size_tcp;

                if(size_tcp < 20){
                    printf("Invalid TCP header length: %u bytes\n", size_tcp);
                } else {
                    unsigned char Port[4]={0};
                    *Port = tcp->sport;
                    *(Port+2) = tcp->dport;
                    // get port id
                    unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                    // cal 
                    if(tcp_tb[flow_id].port_id != index){
                        tcp_tb[flow_id].hamming += popcount32_better(tcp_tb[flow_id].port_id ^ index); // get hamming 
                        tcp_tb[flow_id].port_id = index; // update
                        tcp_tb[flow_id].diffcnt++;
                        // report
                        if(tcp_tb[flow_id].diffcnt > (tdiff/TABLE_SLOT + 3*sqrt(tdvar/TABLE_SLOT))){
                            map_inc(&ipv4_src_addr, inet_ntoa(ipv4->srcAddr));
                            map_inc(&ipv4_dst_addr, inet_ntoa(ipv4->dstAddr));
                        }
                        if(tcp_tb[flow_id].hamming > (thamm/TABLE_SLOT + 3*sqrt(thvar/TABLE_SLOT))){
                            map_inc(&ipv4_src_addr_h, inet_ntoa(ipv4->srcAddr));
                            map_inc(&ipv4_dst_addr_h, inet_ntoa(ipv4->dstAddr));
                        }
                    }
                }
            } else if(ipv4->protocol == (u_char)17){
                udp = (struct sniff_udp*)(packet + SIZE_ETHER + size_ip);
                size_udp = 8; // 8 bytes
                size_existed += size_udp;

                unsigned char Port[4]={0};
                *Port = udp->sport;
                *(Port+2) = udp->dport;
                // get port id
                unsigned int index = crc16(Port, 4) % TABLE_SLOT;
                // cal 
                if(udp_tb[flow_id].port_id != index){
                    udp_tb[flow_id].hamming += popcount32_better(udp_tb[flow_id].port_id ^ index); // get hamming 
                    udp_tb[flow_id].port_id = index; // update
                    udp_tb[flow_id].diffcnt++;
                    // report
                    if(udp_tb[flow_id].diffcnt > (udiff/TABLE_SLOT + 3*sqrt(udvar/TABLE_SLOT))){
                        map_inc(&ipv4_src_addr, inet_ntoa(ipv4->srcAddr));
                        map_inc(&ipv4_dst_addr, inet_ntoa(ipv4->dstAddr));
                    }
                    if(udp_tb[flow_id].hamming > (uhamm/TABLE_SLOT + 3*sqrt(uhvar/TABLE_SLOT))){
                        map_inc(&ipv4_src_addr_h, inet_ntoa(ipv4->srcAddr));
                        map_inc(&ipv4_dst_addr_h, inet_ntoa(ipv4->dstAddr));
                    }
                }
            }
        }
        // Rest part
        payload = (u_char*)(packet + size_existed);
        size_existed = 0; // reset
    } 
    pcap_close(handle);
    
    printf("=============================================================\n");
    const char *key;
    uint32_t reportCntAvg=0, Cnt=0, ReportNum=0;
    float reportCntVar=0.0;
    map_iter_t iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of report counter (diffcnt): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of report counter (diffcnt): %f\n", sqrt(reportCntVar/Cnt));

    iter = map_iter(&ipv4_src_addr);
    while ((key = map_next(&ipv4_src_addr, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr, key);
        if(*map_get(&ipv4_src_addr, key) > (reportCntAvg/Cnt + 2*sqrt(reportCntVar/Cnt))){
            printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports (> mean + 3*var): %d\n", Cnt);
    printf("Number of unique Reports (> reports' mean + 2*var): %d\n", ReportNum);
    printf("=============================================================\n");
    /*iter = map_iter(&ipv4_dst_addr);
    while ((key = map_next(&ipv4_dst_addr, &iter))) {
        printf("%s -> %d\n",  key , *map_get(&ipv4_dst_addr, key));
    }*/
    reportCntAvg=0;
    reportCntVar=0.0;
    Cnt=0;
    ReportNum=0;
    iter = map_iter(&ipv4_src_addr_h);
    while ((key = map_next(&ipv4_src_addr_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_h, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of report counter (hamming): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr_h);
    while ((key = map_next(&ipv4_src_addr_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_h, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of report counter (hamming): %f\n", sqrt(reportCntVar/Cnt));
    iter = map_iter(&ipv4_src_addr_h);
    while ((key = map_next(&ipv4_src_addr_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_h, key);
        if(*map_get(&ipv4_src_addr_h, key) > (reportCntAvg/Cnt + 2*sqrt(reportCntVar/Cnt))){
            printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports (> mean + 3*var): %d\n", Cnt);
    printf("Number of unique Reports (> reports' mean + 2*var): %d\n", ReportNum);
    printf("=============================================================\n");
    /*
    reportCntAvg=0;
    reportCntVar=0.0;
    Cnt=0;
    ReportNum=0;
    printf("N-Records (DiffCnt): \n");
    printf("=============================================================\n");
    iter = map_iter(&ipv4_src_addr_n_d);
    while ((key = map_next(&ipv4_src_addr_n_d, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_d, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of diffCnt (N-records): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr_n_d);
    while ((key = map_next(&ipv4_src_addr_n_d, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_d, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of diffCnt (N-records): %f\n", sqrt(reportCntVar/Cnt));
    iter = map_iter(&ipv4_src_addr_n_d);
    while ((key = map_next(&ipv4_src_addr_n_d, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_d, key);
        if(reportCnt > (reportCntAvg/Cnt + 3*sqrt(reportCntVar/Cnt))){
            printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports (> mean + 3*var): %d\n", Cnt);
    printf("Number of unique Reports (> reports mean + 3*var): %d\n", ReportNum);
    printf("=============================================================\n");
    reportCntAvg=0;
    reportCntVar=0.0;
    Cnt=0;
    ReportNum=0;
    printf("N-Records (Hamming): \n");
    printf("=============================================================\n");
    iter = map_iter(&ipv4_src_addr_n_h);
    while ((key = map_next(&ipv4_src_addr_n_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_h, key);
        reportCntAvg += reportCnt;
        Cnt++;
    }
    printf("Mean of diffCnt (N-records): %f\n", reportCntAvg/(float)Cnt);
    // cal variance
    iter = map_iter(&ipv4_src_addr_n_h);
    while ((key = map_next(&ipv4_src_addr_n_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_h, key);
        reportCntVar += pow(reportCnt - (reportCntAvg/(float)Cnt), 2);
    }
    printf("Variance of diffCnt (N-records): %f\n", sqrt(reportCntVar/Cnt));
    iter = map_iter(&ipv4_src_addr_n_h);
    while ((key = map_next(&ipv4_src_addr_n_h, &iter))) {
        uint32_t reportCnt = *map_get(&ipv4_src_addr_n_h, key);
        if(reportCnt > (reportCntAvg/Cnt + 3*sqrt(reportCntVar/Cnt))){
            printf("%s -> %d\n",  key , reportCnt);
            ReportNum++;
        }
    }
    printf("Number of unique Reports (> mean + 3*var): %d\n", Cnt);
    printf("Number of unique Reports (> reports mean + 3*var): %d\n", ReportNum);
    printf("=============================================================\n");
    */
    return 0;
}