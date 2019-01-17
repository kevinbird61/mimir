#ifndef __STATISTIC__
#define __STATISTIC__

// KV table library
// Ref: https://github.com/rxi/map
#include "cmap/map.h"

/*
    For evaluation: 
    - using "key-value table" structure (constraint the time complexity to O(1))
    - store the statistics of source pcap

    read_pcap_stat: 
    - IPv4:
    | ipv4 IP address | counter value |
    (Also give the entire table size, count the percentage
     of all type of traffic, include those unknown type)

    - TCP/UDP
    | Port number | counter value |

    - (TODO:) TCP/IP 
    | Flow id | counter value |

*/
struct packet_stat {
    // Ethernet
    map_int_t eth_addr_stat;
    map_int_t eth_type_stat;
    // IPv4
    map_int_t ipv4_addr_stat;
    map_int_t ipv4_src_addr;
    map_int_t ipv4_dst_addr;
    map_int_t ipv4_proto_stat;
    // TCP
    map_int_t tcp_port_stat;
    map_int_t tcp_src_port;
    map_int_t tcp_dst_port;
    // UDP
    map_int_t udp_port_stat;
    map_int_t udp_src_port;
    map_int_t udp_dst_port;
};

struct packet_stat* pktStat_init();
void pktStat_inc(map_int_t *m, void *key);

#endif 