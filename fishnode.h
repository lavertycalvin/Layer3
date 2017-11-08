/* fishnode.h */
#ifndef FISHNODE_H
#define FISHNODE_H

#include "fish.h"
#include <stdint.h>

/* constants */
#define MAX_IDS_SEEN 256


#define L2_HEADER_LENGTH 16 	//in bytes -- constant
#define L3_HEADER_LENGTH 14 	//in bytes -- constant

#define FCMP_LENGTH 	 8
#define NEIGH_LENGTH     2
#define BLANK_DV_ADV     2

/* Possible protos for l3_header */
#define L3_PROTO_ECHO 	2
#define L3_PROTO_NEIGH  3
#define L3_PROTO_NAME   4
#define L3_PROTO_DV	7
#define L3_PROTO_FCMP	8
#define L3_PROTO_ARP	9

/* FCMP Error IDs */
#define FCMP_TTL_EXCEEDED     1 
#define FCMP_NET_UNREACHABLE  2
#define FCMP_HOST_UNREACHABLE 3

/* neighbor types */
#define NEIGH_REQUEST  1
#define NEIGH_RESPONSE 2
#define NEIGH_TTL      1

/* structs */
struct neighbor_header{
	uint16_t 	type;
}__attribute__((packed));

struct neighbor_entry{
	fnaddr_t neigh;
	uint32_t ttl;
	uint8_t  valid;
};

struct dv_entry{
	uint8_t  valid;
	char     state;
	fnaddr_t dest;
	fnaddr_t next_hop;
	int 	 metric;
	uint32_t ttl;	
};


struct fishnet_l3_header{
	uint8_t 	ttl;
	uint8_t 	proto;
	uint32_t 	id;
	fnaddr_t 	src;
	fnaddr_t 	dest;
}__attribute__((packed));


struct forwarding_table_entry{
	uint8_t 	valid;
	char 		type;
	fnaddr_t 	dest;
	fnaddr_t 	next_hop;
	int 		metric;
	int	 	prefix_length;
	int 		pkt_count; //why
	uint8_t 	is_best; //printing ">" for some reason
	void *		route_key;
	void *		user_data;
};

struct dv_adv{
	fnaddr_t 	dest;
	fnaddr_t 	netmask;
	uint32_t 	metric;
}__attribute__((packed));

struct dv_packet{
	uint16_t 	num_adv;
	struct dv_adv 	adv_packets; //could be multiple depending on num_adv
}__attribute__((packed));



/* functions */

/* base functionality */
int my_fishnode_l3_receive(void *l3frame, int len);
int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr, uint8_t proto, uint8_t ttl);
int my_fish_l3_forward(void *l3frame, int len);

/* full functionality */
void *my_add_fwtable_entry(fnaddr_t dst, int prefix_length, fnaddr_t next_hop, int metric, char type, void *user_data);
void *my_remove_fwtable_entry(void *route_key);
int my_update_fwtable_metric(void *route_key, int new_metric);
fnaddr_t my_longest_prefix_match(fnaddr_t addr);

#endif 
/* end of fishnode.h */
