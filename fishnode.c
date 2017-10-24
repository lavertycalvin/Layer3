/* Includes Layer 3 implementations for fishnet in CPE 464
 * Author: Calvin Laverty
 *
 */

#include "fishnode.h"
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>

/* =================== Global Vars =========================*/
static int noprompt = 0;
int num_forwarding_table_entries = 0;
int my_forwarding_table_size = 0;


struct forwarding_table_entry *my_forwarding_table;

/* =================== Helper functions! ================== */
void print_my_forwarding_table(){
	fprintf(stderr, ""
	"                    CUSTOM FORWARDING TABLE                      \n"
	"    C = Connected, L = Loopback, N = Broadcast                   \n"
	" B = Neighbor, D = Distance-Vector, Z = Link-State,              \n"
	"                      > = Best                                   \n"
	"=================================================================\n"
	" T      Destination            Next Hop       Metric   Pkt Cnt   \n"
	" - --------------------   -----------------   ------   -------   \n");

	int i = 0;
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid){ //only print if valid
			fprintf(stderr, " %c %20s/%d %20s %4d %4d  \n",
				my_forwarding_table[i].type,
				fn_ntoa(my_forwarding_table[i].dest),
				my_forwarding_table[i].prefix_length,
				fn_ntoa(my_forwarding_table[i].next_hop),
				my_forwarding_table[i].metric,
				my_forwarding_table[i].pkt_count);
		}
	}
}

void resize_forwarding_table(){
	my_forwarding_table_size *= 2;
	fprintf(stderr, "We have to resize our forwarding table. Doubling the size to %d entries!\n", my_forwarding_table_size);
	my_forwarding_table = realloc(my_forwarding_table, sizeof(struct forwarding_table_entry) * my_forwarding_table_size);
	if(my_forwarding_table == NULL){
		fprintf(stderr, "Unable to double the size of the forwarding table, exiting!\n");
		exit(722);
	}
}

void generate_fcmp(uint32_t error, uint32_t id, fnaddr_t packet_dest){
	/* generated fcmp messages to the correct place! */
	/* both id and error are already passed in in network order */
	void *l4frame;
	//malloc for entire packet
	struct fishnet_fcmp_header *fcmp_header = malloc(sizeof(struct fishnet_fcmp_header) + L3_HEADER_LENGTH + L2_HEADER_LENGTH);
	if(fcmp_header == NULL){
		fprintf(stderr, "Unable to malloc for fcmp header in function 'generate_fcmp'. EXITING.\n");
		exit(5);
	}
	//move the fcmp header pointer to the end of the packet
	fcmp_header = (struct fishnet_fcmp_header *)((uint8_t *)fcmp_header + L3_HEADER_LENGTH + L2_HEADER_LENGTH);
	fcmp_header->error   = error;
	fcmp_header->seq_num = id;
	l4frame = fcmp_header; //set the l4frame pointer to the correct place

	fish_l3.fish_l3_send(l4frame, FCMP_LENGTH, packet_dest, FCMP_PROTO, MAX_TTL); 
}

//TO DO
int received_previously(fnaddr_t source, uint32_t packet_id){
	int ret = 0;
	fprintf(stderr, "LMAOOOO. How do we check if we have received_previously?????\n");
	if(source == ALL_NEIGHBORS){
		fprintf(stderr, "Source address was broadcast, not forwarding!\n");
		ret = 1;
	}
	else if(source == fish_getaddress()){
		fprintf(stderr, "Source address was mine, so we have received previously!\n");
		ret = 1;
	}
	
	return ret;
}

/* =================== Basic Implementation ================*/
int my_fishnode_l3_receive(void *l3frame, int len){
	/* Future:
	 * 	Call implementation of fishnet l3 protocols such as DV routing
	 */
	int ret = 1;

	struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;
	int proto = l3_header->proto;
	fnaddr_t src   = l3_header->src;
	/* If l3 dest is node's l3 addr, remove l3 header and pass to l4 code */
	if(l3_header->dest == fish_getaddress()){
		fprintf(stderr, "This packet is meant for me!\n");
		l3_header++; //move pointer to l3 header along
		fish_l4.fish_l4_receive(l3_header, len, proto, src); 
	}
	/* if l3 dest is broadcast ... */
	else if(l3_header->dest == ALL_NEIGHBORS){
		fprintf(stderr, "Dest is Broadcast. Checking if received by node previously...\n");
		/* and received by node previously, drop with no FCMP message */
		if(received_previously(l3_header->src, l3_header->id)){
			fprintf(stderr, "Received previously. Dropping packet!\n");
			//free(l3frame);
		}
		/* frame passed up network stack and forwarded back out over fishnet with decremented ttl */
		else{
			fprintf(stderr, "Not received previously. Forwarding out to fishnet with decremented TTL\n");
			l3_header++; //move pointer to l3 header along
			ret = fish_l4.fish_l4_receive(l3_header, len, proto, src); //pass up network stack
			l3_header--; //move pointer back to original position
			l3_header->ttl -= 1; //decrement ttl
			ret += fish_l3.fish_l3_forward(l3frame, len); //forward back over fishnet	        	
		}
	}
	else{
		fprintf(stderr, "Not broadcast or for us, decrement ttl and forward!\n");
		l3_header->ttl -= 1;
		ret = fish_l3.fish_l3_forward(l3frame, len);
	}	
	
	return ret;
}

int my_fish_l3_send(void *l4frame, int len, fnaddr_t dst_addr, uint8_t proto, uint8_t ttl){
	int ret = 1;
	
	void *l3frame = l4frame + L3_HEADER_LENGTH;
        struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;	
	
	l3_header->ttl   = ttl;
	l3_header->proto = proto;
        l3_header->id    = htonl(fish_next_pktid());
	l3_header->src   = fish_getaddress(); 
	l3_header->dest  = dst_addr;

	ret = fish_l3.fish_l3_forward(l3frame, len);	
	return ret;
}

int is_local(fnaddr_t l3_dest){
	/* returns 1 if local, 0 if not */
	int ret = 0;
	if(l3_dest != fish_getaddress()){
		//fprintf(stderr, "Not local (not for us)\n");
		ret = 1;
	}
	return ret;
}

int my_fish_l3_forward(void *l3frame, int len){
	int ret = 1;
	uint32_t fcmp_error = 0;
	/* NOTE: original frame memory must not be modified */
        struct fishnet_l3_header *l3_header = (struct fishnet_l3_header *)l3frame;	

	/* if TTL is 0 and the dest is not local, drop packet and generate FCMP error message */
	if((l3_header->ttl == 0) && !is_local(l3_header->dest)){
		fprintf(stderr, "TTL is 0 and dest is not local! Generating FCMP packet...\n");
		fcmp_error = htonl(FCMP_TTL_EXCEEDED);
		generate_fcmp(fcmp_error, l3_header->id, l3_header->src);
		//free(l3frame);
		ret = 0;	
	}	
	/* lookup l3 dest in the forwarding table */
	fnaddr_t next_hop = fish_fwd.longest_prefix_match(l3_header->dest);
	/* if there is no route to the destination, drop the frame and generate correct FCMP error message */
	if((ret != 0) && (next_hop == 0)){
		fprintf(stderr, "No route to the destination. Dropping Frame!\n");
		fcmp_error = htonl(FCMP_NET_UNREACHABLE);
		generate_fcmp(fcmp_error, l3_header->id, l3_header->src);
		//free(l3frame);
		ret = 0;

	}
	/* use fish_l2_send to send the frame to the next-hop neighbor indicated by the forwarding table */
	if(ret != 0){
		/* hey! we can send this to l2_send! */
		//might not be the right length tbh
		fish_l2.fish_l2_send(l3frame, next_hop, len); 
	}
	return ret;
}

/* =================== Full Functionality ================= */
void *my_add_fwtable_entry(fnaddr_t dst,
                           int prefix_length,
                           fnaddr_t next_hop,
                           int metric,
                           char type,
                           void *user_data){
	/*lmao how do we store in the table???? */
	fprintf(stderr, "Adding to the table if it exists!\n");
	
	/* check to see if we need to make the table bigger */
	if(num_forwarding_table_entries >= my_forwarding_table_size){
		resize_forwarding_table();
	}	
	
	struct forwarding_table_entry *entry = malloc(sizeof(struct forwarding_table_entry));
	if(entry == NULL){
		fprintf(stderr, "Failed to malloc in function 'my_add_fwtable_entry'. Exiting!\n");
		exit(6);
	}
	

	/* iterate through the table until we find an invalid entry */
	int j = 0;
	while(my_forwarding_table[j++].valid){}	
	
	//found an invalid spot, overwriting!
	my_forwarding_table[j].next_hop      = next_hop;   
	my_forwarding_table[j].dest          = dst;
	my_forwarding_table[j].prefix_length = prefix_length;
	my_forwarding_table[j].type          = type;
	my_forwarding_table[j].metric        = metric;
	my_forwarding_table[j].user_data     = user_data;

	num_forwarding_table_entries++;
	return (void *)1;//this is wrong fo sho.
}

void *my_remove_fwtable_entry(void *route_key){
	int i = 0;
	/* this is definitely not going to work! */
	while(my_forwarding_table[i].route_key != route_key){
		i++;
	}
	my_forwarding_table[i].valid = 0; 	//mark as invalid
	num_forwarding_table_entries--;		//decrement the number of entries in the table
	return my_forwarding_table[i].user_data;//return the user data stored for this entry
}

int my_update_fwtable_metric(void *route_key, int new_metric){
	int update_successful = 0;
	int i = 0;
	/* this is definitely not going to work! */
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid && (my_forwarding_table[i].route_key == route_key)){
				fprintf(stderr, "Found an entry to update!\n");
				my_forwarding_table[i].metric = new_metric;
				update_successful = 1;	
		}	
	}
	
	return update_successful;
}

/* return the best next hop for the proposed address */
fnaddr_t my_longest_prefix_match(fnaddr_t addr){
	fnaddr_t best_match = (fnaddr_t)htonl(0);
	int i = 0, mask = 0, best_match_length = 0, match_length = 0;
	
	for(; i < my_forwarding_table_size; i++){
		if(my_forwarding_table[i].valid){
			/* DOES THE MASK HAVE TO BE IN NETWORK ORDER OR WHAT???? */
			mask = (1 << my_forwarding_table[i].prefix_length) - 1;
			/* mask off the bottom bits of the address????? */
			mask &= ~((1 << (32 - my_forwarding_table[i].prefix_length)) - 1);
			fprintf(stderr, "Checking entry %d in the table\n", i);
			fprintf(stderr, "\tMatching: %s to\n"
					"\tEntry   : %s\n"
					"\tNetmask : %s\n"
					"\tmask    : %d\n",
					fn_ntoa(addr),
					fn_ntoa(my_forwarding_table[i].dest),
					fn_ntoa(htonl(mask)),
					my_forwarding_table[i].prefix_length);
			sleep(3);//temp addition to watch
			/* mask off host bits of addr to compare to table entry */
			if((htonl(mask) & (uint32_t)addr) == (uint32_t)my_forwarding_table[i].dest){
				fprintf(stderr, "Found a match of %d long!!!!!!\n\n", my_forwarding_table[i].prefix_length);
				match_length = my_forwarding_table[i].prefix_length;
				if(match_length > best_match_length){
					fprintf(stderr, "Found a new best next hop %s!\n", fn_ntoa(my_forwarding_table[i].next_hop));
					best_match = my_forwarding_table[i].next_hop;
					best_match_length = match_length;
				}	
			}
					
		}
	}
	fprintf(stderr, "Longest match for %s resolves to next hop %s\n", fn_ntoa(addr), fn_ntoa(best_match));
	return best_match;
}

/* =================== Main implementation =================*/

void sigint_handler(int sig)
{
   if (SIGINT == sig)
	   fish_main_exit();
}

static void keyboard_callback(char *line)
{
   if (0 == strcasecmp("show neighbors", line))
      fish_print_neighbor_table();
   else if (0 == strcasecmp("show arp", line)){ //edited for my own table
      fish_print_arp_table();
   }
   else if (0 == strcasecmp("show route", line))
      fish_print_forwarding_table();
   else if (0 == strcasecmp("show dv", line))
      fish_print_dv_state();
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

   	/* set functions to my custom pointers */
	//fish_l3.fish_l3_send = my_fish_l3_send;
	//fish_l3.fishnode_l3_receive = my_fishnode_l3_receive;
	fish_l3.fish_l3_forward = my_fish_l3_forward;

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
   	fish_enable_neighbor_builtin( 0
   	      | NEIGHBOR_USE_LIBFISH_NEIGHBOR_DOWN
   	);

   	/* Enable the link-state routing protocol.  This requires the neighbor
    	 * protocol to be enabled. */
   	fish_enable_lsarouting_builtin(0);

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


	/* initialize our forwarding table */
	my_forwarding_table = malloc(sizeof(struct forwarding_table_entry) * 256);
	if(my_forwarding_table == NULL){
		fprintf(stderr, "Unable to initialize forwarding table with 256 entries! Exiting!\n");
		exit(52);
	}
	my_forwarding_table_size = 256;

	
	/* Execute the libfish event loop */
	fish_main();

   	/* Clean up and exit */
  	if (!noprompt)
      	printf("\n");

	printf("Fishnode exiting cleanly.\n");
	return 0;
}

