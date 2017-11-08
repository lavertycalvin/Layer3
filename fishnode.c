/* Includes Layer 3 implementations for fishnet in CPE 464
 * Author: Calvin Laverty
 *
 */

#include "fishnode.h"
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

/* ========================================================= */
/* =================== Global Vars ========================= */
/* ========================================================= */
static int noprompt = 0;
int num_forwarding_table_entries = 0;
int my_forwarding_table_size = 0;

int num_packet_ids_stored = 0;

int num_neighbors_stored = 0;
int my_neighbor_table_size = 0;

int num_dv_stored = 0;
int my_dv_table_size = 0;

struct forwarding_table_entry *my_forwarding_table;
struct neighbor_entry *my_neighbor_table;
struct dv_entry *my_dv_table;


void *stored_route_keys;
uint32_t *packet_ids_seen;

/* ========================================================= */
/* =================== Helper functions! =================== */
/* ========================================================= */
void print_my_forwarding_table(){
	fprintf(stdout, ""
	"                    CUSTOM FORWARDING TABLE                      \n"
	"    C = Connected, L = Loopback, B = Broadcast                   \n"
	"  N = Neighbor, D = Distance-Vector, Z = Link-State,             \n"
	"                      > = Best                                   \n"
	"=================================================================\n"
	" T      Destination            Next Hop       Metric   Pkt Cnt   \n"
	" - --------------------   -----------------   ------   -------   \n");

	int i = 0;
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid){ //only print if valid
			fprintf(stdout, " %c%c %16s/%d %19s   %6d    %6d  \n",
				my_forwarding_table[i].type,
				my_forwarding_table[i].is_best,
				fn_ntoa(my_forwarding_table[i].dest),
				my_forwarding_table[i].prefix_length,
				fn_ntoa(my_forwarding_table[i].next_hop),
				my_forwarding_table[i].metric,
				my_forwarding_table[i].pkt_count);
		}
	}
}

/* resize forwarding table, exit if unable to malloc for more space
 * DOUBLES in size each time!
 */
void resize_forwarding_table(){
	my_forwarding_table_size *= 2;
	//fprintf(stderr, "We have to resize our forwarding table. Doubling the size to %d entries!\n", my_forwarding_table_size);
	my_forwarding_table = realloc(my_forwarding_table, sizeof(struct forwarding_table_entry) * my_forwarding_table_size);
	if(my_forwarding_table == NULL){
		fprintf(stderr, "Unable to double the size of the forwarding table, exiting!\n");
		exit(722);
	}
}

void clear_packet_id_table(){
	free(packet_ids_seen);
	packet_ids_seen = calloc(sizeof(uint32_t), 512);
	if(packet_ids_seen == NULL){
		fprintf(stderr, "Unable to re-initialize packet ids seen array with 512 entries! Exiting!\n");
		exit(53);
	}
	num_packet_ids_stored = 0;

}

void add_id_seen(uint32_t id){
	if(num_packet_ids_stored == MAX_IDS_SEEN){
		clear_packet_id_table();
	}	
	packet_ids_seen[num_packet_ids_stored] = id;
	num_packet_ids_stored++;	
}

/* checks to see if the id is seen, returns 1 if already stored, 0 otherwise */
uint8_t check_id_seen(uint32_t id){
	uint8_t ret = 0;
	int i = 0;
	for(; i < num_packet_ids_stored; i++){
		if(packet_ids_seen[i] == id){
			//fprintf(stderr, "Definitely already saw this packet.....\n");
			ret = 1;
		}
	}
	return ret;
}

int received_previously(fnaddr_t source, uint32_t packet_id){
	int ret = 0;
	if(source == ALL_NEIGHBORS){
		/*check to see if we already recieved this packet id! */
		ret = check_id_seen(packet_id);
		//fprintf(stderr, "Source address was broadcast, not forwarding!\n");
	}
	else if(source == fish_getaddress()){
		//fprintf(stderr, "Source address was mine, so no need to forward!!\n");
		ret = 1;
	}
	else{
		//fprintf(stderr, "Source was not us or broadcast.... is that right?\n");
		ret = check_id_seen(packet_id);
	}
	return ret;
}

/* takes in the netmask ALREADY IN HOST ORDER and calculates the prefix length */
int find_prefix_length(uint32_t netmask){
	//fprintf(stderr, "Calculating prefix length for %s!!!!\n", fn_ntoa(htonl(netmask)));
	int length = 0;
	while(netmask > 0){
		netmask = netmask >> 1;
		length++;
	}	
	//fprintf(stderr, "\tPrefix length is %d\n", length);
	return length;
}

/* takes in a destination and metric ALREADY IN HOST ORDER and returns the char of the advertisement type */
char find_advertisement_type(fnaddr_t dest, uint32_t metric){
	char type = (char)35; //this is completely random...
	//fprintf(stderr, "\nTrying to find the advertisement type for metric of %d\n", metric);
	if(dest == fish_getaddress()){
		//fprintf(stderr, "\tDest is equal to my address, noting as 'LINK-STATE' (loopback?)\n");
		type = FISH_FWD_TYPE_LS; 
	}
	else if(dest == ALL_NEIGHBORS){
		//fprintf(stderr, "\tDest is equal to Broadcast,  noting as 'Broadcast'\n");
		type = FISH_FWD_TYPE_BROADCAST;
	}
	else{
		if(metric == 1){
			//fprintf(stderr, "\tMetric is 1, designated as connected????\n");
			type = FISH_FWD_TYPE_NEIGHBOR;
		}
		else{
			//fprintf(stderr, "\tDesignating advertisement as Distance Vector\n");
			type = FISH_FWD_TYPE_DV;
		}	
	}
	return type;
}

/* ========================================================= */
/* ============ Overriding Forwarding table Funcs ========= */
/* ========================================================= */
int dv_fwtable_iterator_cb(void *callback_data, fnaddr_t dest, int prefix_len, fnaddr_t next_hop, int metric, void *entry_data){
	/* callback data SHOULD	be a dv frame entry */
	
	int prefix_length = 0;
	char connection_type = 5;
	struct dv_packet *dv = (struct dv_packet *)callback_data;
	fprintf(stderr, "\nDV PACKET\n"
			"\tPacket Source is: %s\n"
			"\tNumber of adv in this packet: %d\n", fn_ntoa(dest), ntohs(dv->num_adv));
	int i = 0;
	struct dv_adv *advertisement = &dv->adv_packets; //set the advertisement to point to the packets 
	while(i < ntohs(dv->num_adv)){
		/* calc the netmask */
		/* check out the metric */
		/*
		 */
		fprintf(stderr, "\n\tAdvertisement number %d:\n"
				"\t\tDest is: %s\n", i, fn_ntoa(advertisement->dest));
		fprintf(stderr, "\t\tNetmask: %s\n"
				"\t\tMetric : %d\n",
				fn_ntoa(advertisement->netmask),
				ntohl(advertisement->metric));
		prefix_length = find_prefix_length(ntohl(advertisement->netmask));
		//connection_type = find_advertisement_type(advertisement->dest, ntohl(advertisement->metric));
		/* connection type should be DV since it's a dv packet.... */
		connection_type = 'D';
		fprintf(stderr, "\t\tConnection type: %c\n"
				"\t\tPrefix Length  : %d\n",
				connection_type, prefix_length);
		/* by default adds to the table currently */
		//add_return = fish_fwd.add_fwtable_entry(advertisement->dest, prefix_length, dv_packet_source, 
		//				  ntohl(advertisement->metric) - 1, connection_type, 0); //last entry is user data
		//fprintf(stderr, "Value of add_return is: %lu\n", (unsigned long)add_return);
		advertisement++;
		i++;
		
	}
	return 0;
}


void my_iterate_entries(fwtable_iterator_cb callback, void *callback_param, char type){
	int callback_ret = 0;
	int i = 0;
	
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid && (my_forwarding_table[i].type == type)){
			fprintf(stderr, "Found an entry to update!\n");
			callback_ret = callback(callback_param, my_forwarding_table[i].dest,
								my_forwarding_table[i].prefix_length,
								my_forwarding_table[i].next_hop,
								my_forwarding_table[i].metric,
								my_forwarding_table[i].user_data);
			if(callback_ret){
				/* we need to delete this entry */
				fprintf(stderr, "We need to remove entry %d!\n", i);
				//fish_fwd.remove_fwtable_entry(
			}
		}	
	}
	
}

/* ========================================================= */
/* ============== Basic DV Routing Implementation ========== */ 
/* ========================================================= */
void print_my_dv_table(){

	fprintf(stderr, "             MY DISTANCE VECTOR ROUTING STATE                 \n"
  	                "A = Active, B = Backup, W = Withdrawn, > = In FWD Table       \n"
	                "===========================================================   \n"
	                "S      Destination            Next Hop       Dist   TTL       \n"
 			"- --------------------   -----------------   ----   ---       \n");
	int i = 0;
	for(; i < my_dv_table_size; i++){
		if(my_dv_table[i].valid){
			fprintf(stderr, "%c %16s", my_dv_table[i].state, fn_ntoa(my_dv_table[i].dest));
			fprintf(stderr, "%16s %3d %3d\n", fn_ntoa(my_dv_table[i].next_hop), my_dv_table[i].metric, my_dv_table[i].ttl);
		}
	}

}

void resize_dv_table(){
	my_dv_table_size *= 2;
	
	my_dv_table = realloc(my_dv_table, my_dv_table_size * sizeof(struct dv_entry));
       	if(my_dv_table == NULL){
		fprintf(stderr, "Unable to realloc for dv table of size %d. Exiting...\n", my_dv_table_size);
		exit(1231);
	}
}

int in_forwarding_table(fnaddr_t dest){
	int i = 0;	
}

void add_to_dv_table(char state, fnaddr_t dest, fnaddr_t next_hop, int metric, fnaddr_t netmask){
	if(num_dv_stored >= my_dv_table_size){
		resize_dv_table();
	}
 	int i = 0;	
	while(my_dv_table[i].valid){
		i++;
	}

	my_dv_table[i].valid    = 1;
	my_dv_table[i].state    = 'A';
	my_dv_table[i].dest     = dest;
	my_dv_table[i].next_hop = next_hop;
	my_dv_table[i].metric   = metric;
        my_dv_table[i].ttl      = 180;	

	num_dv_stored += 1;

	//check to see if already in the forwarding table
	if(in_forwarding_table(dest)){
		//if so, check to see if this metric is better!
		
	}
	else{
		fish_fwd.add_fwtable_entry(dest, find_prefix_length(netmask), next_hop, metric, 'D', 0);
	}	
}

void decrement_dv_table(){
	int i = 0;
	for(; i < my_dv_table_size; i++){
		if(my_dv_table[i].valid){
			my_dv_table[i].ttl -= 1;
		}
		if(my_dv_table[i].ttl == 0){
			//decide to mark as withdrawn or remove
			if((my_dv_table[i].state == 'A') || (my_dv_table[i].state == 'B')){
				fprintf(stderr, "Marking %s as stale!\n", fn_ntoa(my_dv_table[i].dest));
				//if state is 'A' and moving to 'W', update the shortest backup route to 'A'
				if(my_dv_table[i].state == 'A'){
					
				}
				my_dv_table[i].state  = 'W';
				
				my_dv_table[i].ttl    = 180;
				my_dv_table[i].metric = MAX_TTL;
			
				//remove from forwarding table
			}
			//if withdrawn
			else if(my_dv_table[i].state == 'W'){
				fprintf(stderr, "Removing %s from dv table!!\n", fn_ntoa(my_dv_table[i].dest));
				my_dv_table[i].valid = 0;
			}
			else{
				fprintf(stderr, "WTF state is this?!\n");
			}	
		}
	}
	//schedule for a second in the future
	fish_scheduleevent(100, decrement_dv_table, 0);
}

/* takes in a distance vector routing frame and calls iterate entries for all dv entries */
void process_dv_packet(void *dv_frame, fnaddr_t dv_packet_source, int len){
	fish_fwd.iterate_entries(dv_fwtable_iterator_cb, dv_frame, FISH_FWD_TYPE_DV);
}

void send_blank_dv_advertisement(){
	void *l4frame = malloc(sizeof(struct dv_packet) + L2_HEADER_LENGTH + L3_HEADER_LENGTH);
	if(l4frame == NULL){
		fprintf(stderr, "Unable to malloc for empty dv advertisement, Exiting... \n");
		exit(445);
	}
	l4frame += L2_HEADER_LENGTH + L3_HEADER_LENGTH;
	
	struct dv_packet *blank = l4frame;
	blank->num_adv = 0;

	//send the blank advertisement to all neighbors with a TTL of 1
	fish_l3.fish_l3_send(blank, BLANK_DV_ADV, ALL_NEIGHBORS, L3_PROTO_DV, 1);
}

void advertise_dv(){
	fprintf(stderr, "\nBROADCASTING WITH 0 ADVERTISEMENTS!\n");
	send_blank_dv_advertisement();
	fish_scheduleevent(30000, advertise_dv, 0);
}


void advertise_full_dv();

/* ========================================================= */
/* ================ Neighbor Implementation ================ */
/* ========================================================= */
void print_my_neighbor_table(){
       fprintf(stderr,"\n" 
		"           NEIGHBOR TABLE         \n"
		" =================================\n"
		"     Neighbor           TTL       \n"
		" ----------------      -----      \n");

       int i = 0;
       for(; i < my_neighbor_table_size; i++){
       		if(my_neighbor_table[i].valid){
			fprintf(stderr, "%16s       %d\n", fn_ntoa(my_neighbor_table[i].neigh), my_neighbor_table[i].ttl);
		}
       }
}

void decrement_neighbor_table(){
	//decrement the ttl on every valid neighbor!
	int i = 0;
	for(; i < num_neighbors_stored; i++){
		if(my_neighbor_table[i].valid){
			my_neighbor_table[i].ttl -= 1;
			if(my_neighbor_table[i].ttl == 0){
				//mark as invalid!
				my_neighbor_table[i].valid = 0;
			}
		}
	}
	//schedule this to happen again in 1 second!
	fish_scheduleevent(1000, decrement_neighbor_table, 0);
}

/* resize table... checking is handled by function add_neighbor_to_table */
void resize_neighbor_table(){
	//double the table and try and realloc for the space!
	my_neighbor_table_size *= 2;

	my_neighbor_table = realloc(my_neighbor_table, my_neighbor_table_size * sizeof(struct neighbor_entry)); 
	if(my_neighbor_table == NULL){
		fprintf(stderr, "Unable to double the size of the neighbor table to %d! Exiting...\n", my_neighbor_table_size);
		exit(1234);
	}

}

void add_neighbor_to_table(fnaddr_t neigh){
	if(num_neighbors_stored >= my_neighbor_table_size){
		fprintf(stderr, "Need to make a bigger neighbor table!\n");
		resize_neighbor_table();
	}
	int i = 0;
	while(my_neighbor_table[i].valid){
		if(my_neighbor_table[i].neigh == neigh){
			//fprintf(stderr, "Heard from the same neighbor: %s! Refreshing TTL!\n", fn_ntoa(neigh));
			//currently, the way this is written could have multiple entries for the same neighbors.... but it should be ok!
			my_neighbor_table[i].ttl = 120;
			return;
		}
		i++;
	}
	
	fprintf(stderr, "New Neighbor: %s\n", fn_ntoa(neigh));
	//now we have an open spot!
	my_neighbor_table[i].neigh = neigh;
	my_neighbor_table[i].ttl   = 120;
	my_neighbor_table[i].valid = 1;
	num_neighbors_stored += 1;

	//add to forwarding table here????
	fish_fwd.add_fwtable_entry(neigh, 32, neigh, 1, 'N', 0);
}

void send_neigh_response(fnaddr_t source){
	//fprintf(stderr, "\tSending a neighbor response packet\n");	
	
	void *neighbor_packet = malloc(L2_HEADER_LENGTH + L3_HEADER_LENGTH + sizeof(struct neighbor_header));
	if(neighbor_packet == NULL){
		fprintf(stderr, "Unable to malloc for neighbor response packet, Exiting!\n");
		exit(667);
	}
	neighbor_packet += L2_HEADER_LENGTH + L3_HEADER_LENGTH;//set pointer to point to neigh packet
	
	struct neighbor_header *neigh = (struct neighbor_header *)neighbor_packet;
	neigh->type = htons(NEIGH_RESPONSE);
	
	fish_l3.fish_l3_send(neighbor_packet, NEIGH_LENGTH, source, L3_PROTO_NEIGH, NEIGH_TTL);
}

void send_neigh_request(){
	//fprintf(stderr, "\tSending a neighbor request packet\n");
	void *neighbor_packet = malloc(L2_HEADER_LENGTH + L3_HEADER_LENGTH + sizeof(struct neighbor_header));
	
	if(neighbor_packet == NULL){
		fprintf(stderr, "Unable to malloc for neighbor request packet, Exiting!\n");
		exit(666);
	}
	neighbor_packet += L2_HEADER_LENGTH + L3_HEADER_LENGTH;//set pointer to point to neigh packet
	
	struct neighbor_header *neigh = (struct neighbor_header *)neighbor_packet;
	neigh->type = htons(NEIGH_REQUEST);

	fish_l3.fish_l3_send(neigh, NEIGH_LENGTH, ALL_NEIGHBORS, L3_PROTO_NEIGH, NEIGH_TTL);
	//free(neighbor_packet);
}

void process_neighbor_packet(void *neigh_frame, fnaddr_t neigh_source, int len){
	//fprintf(stderr, "\nNEIGHBOR PACKET\n");
	struct neighbor_header *neigh = (struct neighbor_header *)neigh_frame;
	if(ntohs(neigh->type) == NEIGH_REQUEST){
		send_neigh_response(neigh_source);
	}
	else{
		//received a response, add to forwarding table????
		//fprintf(stderr, "\tReceived a Neighbor response from %s\n", fn_ntoa(neigh_source));
		add_neighbor_to_table(neigh_source);
	}	
}

void timed_neighbor_probe(){
	/* probe the network every 30 seconds! 
	 * NOTE: if a neighbor has not been heard from in 2 minutes, remove!
	 */
	//fprintf(stderr, "\nSENDING OUT A NEIGHBOR PROBE!\n");
	send_neigh_request();
	fish_scheduleevent(30000, timed_neighbor_probe, 0);
}	

/* ========================================================= */
/* =================== Basic Implementation ================ */
/*========================================================== */
int my_fishnode_l3_receive(void *l3frame, int len){
	int ret = 1;

	struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;
	int proto = l3_header->proto;
	fnaddr_t src   = l3_header->src;
	
	/* If l3 dest is node's l3 addr, remove l3 header and pass to l4 code */
	if(l3_header->dest == fish_getaddress()){
		//fprintf(stderr, "This packet is meant for me!\n");
		
		/* check if dv packet */
		if(l3_header->proto == L3_PROTO_DV){
			l3_header++; //move pointer to l3 header along to point to l4frame
			process_dv_packet(l3_header, src, len - L3_HEADER_LENGTH);	
			l3_header--;
		}
		else if(l3_header->proto == L3_PROTO_NEIGH){
			l3_header++; //move pointer to l3 header along to point to l4frame
			process_neighbor_packet(l3_header, src, len - L3_HEADER_LENGTH);	
			l3_header--;
		}	
		l3_header++; //move pointer to l3 header along
		fish_l4.fish_l4_receive(l3_header, len - L3_HEADER_LENGTH, proto, src); 
	}
	
	/* if l3 dest is broadcast ... */
	else if(l3_header->dest == ALL_NEIGHBORS){
		//fprintf(stderr, "Dest is Broadcast. Checking if received by node previously...\n");
		/* and received by node previously, drop with no FCMP message */
		
		/* print out this frame... seems odd. */
		//fish_debugframe(7, "BROADCAST DEST???", l3frame, 3, len + L3_HEADER_LENGTH, 9);
		
		if(!received_previously(l3_header->src, l3_header->id)){
			/* add packet ID as seen already! */
			add_id_seen(l3_header->id);
			

			if(l3_header->proto == L3_PROTO_DV){
				l3_header++; //move pointer to l3 header along
				//fprintf(stderr, "Received a DV packet broadcast to all nodes\n");
				process_dv_packet(l3_header, src, len - L3_HEADER_LENGTH);	
				l3_header--;
			}	
			else if(l3_header->proto == L3_PROTO_NEIGH){
				l3_header++; //move pointer to l3 header along to point to l4frame
				process_neighbor_packet(l3_header, src, len - L3_HEADER_LENGTH);	
				l3_header--;
			}	
			
			l3_header++; //move pointer to l3 header along
			ret = fish_l4.fish_l4_receive(l3_header, len - L3_HEADER_LENGTH, proto, src); //pass up network stack
			l3_header--; //move pointer back to original position
			l3_header->ttl -= 1; //decrement ttl
			ret += fish_l3.fish_l3_forward(l3frame, len); //forward back over fishnet	
		}
	}
	else{
		//fprintf(stderr, "Not broadcast or for us, decrement ttl and forward!\n");
		l3_header->ttl -= 1;
		ret = fish_l3.fish_l3_forward(l3frame, len);
	}	
	return ret;
}

int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr, uint8_t proto, uint8_t ttl){
	int ret = 1;
	
	void *l3frame = malloc(sizeof(struct fishnet_l3_header) + len);
	if(l3frame == NULL){
		fprintf(stderr, "Failed to malloc for function: my_fish_l3_send\n");
	}
	
	l3frame += L3_HEADER_LENGTH; //move the pointer to start of l3 header
	memcpy(l3frame, l4frame, len);
 	l3frame -= L3_HEADER_LENGTH; //move back to the original spot
	
        struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;	
	
	l3_header->ttl   = ttl;
	l3_header->proto = proto;
        l3_header->id    = htonl(fish_next_pktid());
	l3_header->src   = fish_getaddress(); 
	l3_header->dest  = dst_addr;
	
	add_id_seen(l3_header->id);

	ret = fish_l3.fish_l3_forward(l3frame, len + L3_HEADER_LENGTH);	
	return ret;
}

int is_local(fnaddr_t l3_dest){
	/* returns 1 if local, 0 if not */
	int ret = 0;
	if(l3_dest == fish_getaddress()){
		//fprintf(stderr, "Not local (not for us)\n");
		ret = 1;
	}
	return ret;
}

int my_fish_l3_forward(void *l3frame, int len){
	fnaddr_t next_hop = (fnaddr_t)0;
        
	struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;	

	//fish_debugframe(7, "TEMP THING", l3frame, 3, len, 9);
	/* if TTL is 0 and the dest is not local, drop packet and generate FCMP error message */
	if((l3_header->ttl == 0) && !is_local(l3_header->dest)){
		fish_fcmp.send_fcmp_response(l3frame, len, FCMP_TTL_EXCEEDED);
		return 0;	
	}	
	
	/* Broadcast SHOULD be in the forwarding table, but we will see. */
	/* NOTE: Apparently not... */
	if(l3_header->dest == ALL_NEIGHBORS){
		next_hop = ALL_NEIGHBORS;
	}
	else{
		fprintf(stderr, "Looking for best match in forwarding table for: %s\n", fn_ntoa(l3_header->dest)); 
		next_hop = fish_fwd.longest_prefix_match(l3_header->dest);
	}
	/* if there is no route to the destination, drop the frame and generate correct FCMP error message */
	if(next_hop == 0){
		//fprintf(stderr, "No route to the destination. Dropping Frame!\n");
		fish_fcmp.send_fcmp_response(l3frame, len, FCMP_NET_UNREACHABLE);
		return 0;

	}
	/* use fish_l2_send to send the frame to the next-hop neighbor indicated by the forwarding table */
	//fprintf(stderr, "Sending the packet to hop %s with length %d\n", fn_ntoa(next_hop), len);
	add_id_seen(l3_header->id);
	fish_l2.fish_l2_send(l3frame, next_hop, len); 

	/* do we need to add the frame to the routing table here too? */
	return 1;
}

/* ========================================================= */
/* =================== Full Functionality ================== */
/* ========================================================= */
void *my_add_fwtable_entry(fnaddr_t dst,
                           int prefix_length,
                           fnaddr_t next_hop,
                           int metric,
                           char type,
                           void *user_data){
	fprintf(stderr, "Adding to the table if it exists!\n");
	
	/* check to see if we need to make the table bigger */
	if(num_forwarding_table_entries >= my_forwarding_table_size){
		resize_forwarding_table();
	}	
	
	/* iterate through the table until we find an invalid entry */
	int j = 0;
	while(my_forwarding_table[j].valid){
		j++;
	}	
	
	fprintf(stderr, "Found an invalid/empty spot at position %d in table, overwriting!\n", j);
	my_forwarding_table[j].next_hop      = next_hop;   
	my_forwarding_table[j].dest          = dst;
	my_forwarding_table[j].prefix_length = prefix_length;
	my_forwarding_table[j].type          = type;
	my_forwarding_table[j].metric        = metric;
	my_forwarding_table[j].user_data     = user_data; //place in dv table!!!!
	my_forwarding_table[j].valid         = 1;
	my_forwarding_table[j].is_best       = '>'; //temporary, not everything should be the best!

	num_forwarding_table_entries++;
	
	/* return the pointer to the entry */
	return (void *)&my_forwarding_table[j];
}

void *my_remove_fwtable_entry(void *route_key){
	/* route key is the address in the forwarding table
	 * cast to an entry and mark as invalid then return the user data with it????
	 */
	fprintf(stderr, "Removing an entry from the forwarding table!\n");
	/* this is definitely not going to work! */
	((struct forwarding_table_entry *)(route_key))->valid = 0; 	//mark as invalid
	num_forwarding_table_entries--;		//decrement the number of entries in the table
	return ((struct forwarding_table_entry *)(route_key))->user_data;//return the user data stored for this entry
}

int my_update_fwtable_metric(void *route_key, int new_metric){
	int update_successful = 1;

	/* this is definitely not going to work! */
	((struct forwarding_table_entry *)(route_key))->metric = new_metric;

	return update_successful;
}

/* return the best next hop for the proposed address */
fnaddr_t my_longest_prefix_match(fnaddr_t addr){
	fnaddr_t best_match = (fnaddr_t)htonl(0);
	int i = 0, best_match_length = 0, match_length = 0;
	uint32_t mask = 0;
	
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid){
			/* DOES THE MASK HAVE TO BE IN NETWORK ORDER OR WHAT???? */
			mask = ~((1 << (my_forwarding_table[i].prefix_length)) - 1);
			fprintf(stderr, "Checking entry %d in the table\n", i);
			fprintf(stderr, "\tMatching: %s to\n", fn_ntoa(my_forwarding_table[i].dest));
			fprintf(stderr, "\tEntry   : %s\n", fn_ntoa(addr));
			fprintf(stderr, "\tNetmask : %s\n"
					"\tmask    : %d\n",
					fn_ntoa(ntohl(mask)),
					my_forwarding_table[i].prefix_length);
			sleep(1);//temp addition to watch
			/* mask off host bits of addr to compare to table entry */
			if((htonl(mask) & (uint32_t)addr) == (uint32_t)my_forwarding_table[i].dest){
				//fprintf(stderr, "Found a match of %d long!!!!!!\n\n", my_forwarding_table[i].prefix_length);
				match_length = my_forwarding_table[i].prefix_length;
				if(match_length > best_match_length){
					fprintf(stderr, "\n\t\tFound a new best next hop %s!\n\n", fn_ntoa(my_forwarding_table[i].next_hop));
					best_match = my_forwarding_table[i].next_hop;
					best_match_length = match_length;
				}	
			}
					
		}
	}
	fprintf(stderr, "\n================================================\n");
	fprintf(stderr, "Longest Match resolves to next hop: %s", fn_ntoa(best_match));
	fprintf(stderr, "\n================================================\n\n");
	return best_match;
}

/* ========================================================= */
/* =================== Main implementation ================= */
/* ========================================================= */

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      print_my_neighbor_table();
   else if (0 == strcasecmp("show arp", line)){ //edited for my own table
      fish_print_arp_table();
   }
   else if (0 == strcasecmp("show route", line)){
      print_my_forwarding_table();
   }
   else if (0 == strcasecmp("show dv", line))
      print_my_dv_table();
   else if (0 == strcasecmp("quit", line) || 0 == strcasecmp("exit", line))
      fish_main_exit();
   else if (0 == strcasecmp("show topo", line))
      fish_print_lsa_topo();
   else if (0 == strcasecmp("help", line) || 0 == strcasecmp("?", line)) {
      printf("Available commands are:\n"
             "    exit                         Quit the fishnode\n"
             "    help                         Display this message\n"
             "    quit                         Quit the fishnode\n"
             "    show arp                     Display the ARP table\n"
             "    show dv                      Display the dv routing state\n"
             "    show neighbors               Display the neighbor table\n"
             "    show route                   Display the forwarding table\n"
             "    show topo                    Display the link-state routing\n"
             "                                 algorithm's view of the network\n"
             "                                 topology\n"
             "    ?                            Display this message\n"
            );
   }
   else if (line[0] != 0)
      printf("Type 'help' or '?' for a list of available commands.  "
             "Unknown command: %s\n", line);

   if (!noprompt)
      printf("> ");

   fflush(stdout);
}

int main(int argc, char **argv)
{
	struct sigaction sa;
   	int arg_offset = 1;

   	/* ===================================
	 * =================================== 
	
	 * set functions to my custom pointers */
	fish_l3.fish_l3_send = my_fish_l3_send;
	fish_l3.fishnode_l3_receive = my_fishnode_l3_receive;
	fish_l3.fish_l3_forward = my_fish_l3_forward;

	/* custom pointers for advanced functionality */
	fish_fwd.add_fwtable_entry     = my_add_fwtable_entry;
	fish_fwd.remove_fwtable_entry  = my_remove_fwtable_entry;
	fish_fwd.update_fwtable_metric = my_update_fwtable_metric;
	fish_fwd.longest_prefix_match  = my_longest_prefix_match;
   	/* ===================================
	 * =================================== */
	
	
	/* Verify and parse the command line parameters */
	if (argc != 2 && argc != 3 && argc != 4)
	{
		printf("Usage: %s [-noprompt] <fishhead address> [<fn address>]\n", argv[0]);
		return 1;
	}

   	if (0 == strcasecmp(argv[arg_offset], "-noprompt")) {
      		noprompt = 1;
      		arg_offset++;
   	}

   	/* Install the signal handler */
	sa.sa_handler = sigint_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (-1 == sigaction(SIGINT, &sa, NULL))
	{
		perror("Couldn't set signal handler for SIGINT");
		return 2;
	}

   	/* Set up debugging output */
//#ifdef DEBUG
	fish_setdebuglevel(FISH_DEBUG_ALL);
//#else
	//fish_setdebuglevel(FISH_DEBUG_NONE);
//#endif
	fish_setdebugfile(stderr);

   	/* Join the fishnet */
	if (argc-arg_offset == 1)
		fish_joinnetwork(argv[arg_offset]);
	else
		fish_joinnetwork_addr(argv[arg_offset], fn_aton(argv[arg_offset+1]));

   	/* Install the command line parsing callback */
   	fish_keybhook(keyboard_callback);
   	if (!noprompt)
      	printf("> ");
   	fflush(stdout);

   	/* Enable the built-in neighbor protocol implementation.  This will discover
    	 * one-hop routes in your fishnet.  The link-state routing protocol requires
   	 * the neighbor protocol to be working, whereas it is redundant with DV.
   	 * Running them both doesn't break the fishnode, but will cause extra routing
   	 * overhead */
   	//fish_enable_neighbor_builtin( 0
   	//      | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
   	//);

   	/* Enable the link-state routing protocol.  This requires the neighbor
    	 * protocol to be enabled. */
   	//fish_enable_lsarouting_builtin(0);

   	/* Full-featured DV routing.  I suggest NOT using this until you have some
    	 * reasonable expectation that your code works.  This generates a lot of
    	 * routing traffic in fishnet */

   	//fish_enable_dvrouting_builtin( 0
   	 //    | DVROUTING_WITHDRAW_ROUTES
         //| DVROUTING_TRIGGERED_UPDATES
   	 //    | RVROUTING_USE_LIBFISH_NEIGHBOR_DOWN
   	 //    | DVROUTING_SPLIT_HOR_POISON_REV
   	 //    | DVROUTING_KEEP_ROUTE_HISTORY
   	//);

	
	/* initialize our dv table */
	my_dv_table = calloc(sizeof(struct dv_entry), 128);
	if(my_dv_table == NULL){
		fprintf(stderr, "Unable to initialize dv table with 128 entries! Exiting!\n");
		exit(51);
	}
	my_dv_table_size = 128;
	
	/* initialize our forwarding table */
	my_forwarding_table = calloc(sizeof(struct forwarding_table_entry), 256);
	if(my_forwarding_table == NULL){
		fprintf(stderr, "Unable to initialize forwarding table with 256 entries! Exiting!\n");
		exit(52);
	}
	my_forwarding_table_size = 256;

	/* initialize our struct of packet ids seen */
	packet_ids_seen = calloc(sizeof(uint32_t), 512);
	if(packet_ids_seen == NULL){
		fprintf(stderr, "Unable to initialize packet ids seen array with 512 entries! Exiting!\n");
		exit(53);
	}
	
	/* start our 30 second timed functions for neighbor and dv advertisements */
	timed_neighbor_probe();
	advertise_dv();
	
	/*make our neighbors table */

	my_neighbor_table = calloc(sizeof(struct neighbor_entry), 64);
	if(my_neighbor_table == NULL){
		fprintf(stderr, "Unable to initialize neighbor table with 64 entries! Exiting!\n");
		exit(54);
	}
	my_neighbor_table_size = 64;

	
	/* start our decrement of the table */
	decrement_neighbor_table();
	
	
	/* Execute the libfish event loop */
	fish_main();

   	/* Clean up and exit */
  	if (!noprompt)
      	printf("\n");

	printf("Fishnode exiting cleanly.\n");
	return 0;
}
