#include "packet_stat.h"
#include "stdlib.h"
#include "stdint.h"

struct packet_stat* pktStat_init(){
    struct packet_stat* pktStat = (struct packet_stat*)malloc(sizeof(struct packet_stat));

    // call map init
    map_init(&pktStat->eth_addr_stat);
    map_init(&pktStat->eth_type_stat);
    map_init(&pktStat->ipv4_addr_stat);
    map_init(&pktStat->ipv4_proto_stat);
    map_init(&pktStat->tcp_port_stat);
    map_init(&pktStat->udp_port_stat);

    return pktStat;
}

void pktStat_inc(map_int_t *m, void *key){
    int *ori = map_get(m, key);
    if(ori){
        map_set(m, key, (*ori)+1 );
    } else {
        map_set(m, key, 1);
    }
}
