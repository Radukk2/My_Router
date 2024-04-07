#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"



/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *arp_table;
int arp_table_len;


struct route_table_entry *get_best_route(uint32_t ip_dest) {
	for (int i = 0; i < rtable_len; i++) {
    	if (rtable[i].prefix == (rtable[i].mask & ip_dest)) {
      		return &rtable[i];
    	}
	}
	return NULL;
}

struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
      		return &arp_table[i];
    	}
	} 
	return NULL;
}

int main(int argc, char *argv[])
{

	// Do not modify this line
	init(argc - 2, argv + 2);

	char buf[MAX_PACKET_LEN];
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory");
	arp_table = malloc(sizeof(struct  arp_table_entry) * 50);
	DIE(arp_table == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt" , arp_table);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

		if (eth_hdr->ether_type != ntohs(ETHERTYPE_IP)) {
			printf("Ignored non-IPv4 packet\n");
			continue;
		}
		
		uint16_t ip_sum =  ntohs(ip_hdr->check);
		ip_hdr->check = 0;
		uint16_t check =  checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

		if (check != ip_sum) {
			 continue;
		}
		printf("%d\n", check);
		struct route_table_entry *best = get_best_route(ip_hdr->daddr);
		if (!best) {
			continue;
		}
		printf("%d\n", 1);
		if (ip_hdr->ttl >= 1) {
			ip_hdr->ttl--;
		} else {
			continue;
		}
		ip_hdr->check = 0;
		check =  checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		ip_hdr->check = htons(check);
		uint8_t add_mac[6];
		struct arp_table_entry *mac1 = get_mac_entry(ip_hdr->daddr);
		if (!mac1)
			continue;
		get_interface_mac(interface, add_mac);
		memcpy(eth_hdr->ether_dhost, mac1->mac, sizeof(mac1->mac));
		memcpy(eth_hdr->ether_shost, add_mac, sizeof(add_mac));
		send_to_link(best->interface, buf, len);
	}
}
