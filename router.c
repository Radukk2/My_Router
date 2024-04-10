#include <arpa/inet.h> /* ntoh, hton and inet_ functions */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
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

int comp_function(const void *a, const void *b) {
    const struct route_table_entry *r1 = (const struct route_table_entry *)a;
    const struct route_table_entry *r2 = (const struct route_table_entry *)b;
    return r2->mask - r1->mask;
}


int send_no_route(int interface, char *msg, struct ether_header *eth, struct iphdr *first_ip, struct iphdr *last_ip, char *data)
{
	//icmp creation
	struct icmphdr *icmp = calloc(1, sizeof(struct icmphdr));
	icmp->type = 3;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->checksum = checksum((uint16_t *)icmp, sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);

	//new packet
	char *new_buff = malloc(sizeof(struct icmphdr) + sizeof(struct iphdr) * 2 + sizeof(struct ether_header) + 8);
	memcpy(new_buff, eth, sizeof(struct ether_header));
	memcpy(new_buff + sizeof(struct ether_header), first_ip, sizeof(struct iphdr));
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header), icmp, sizeof(struct icmphdr));
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr), last_ip, sizeof(struct iphdr)); 
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr) * 2, data, 8);
	send_to_link(interface, new_buff, sizeof(struct icmphdr) + sizeof(struct iphdr) * 2 + sizeof(struct ether_header) + 8);
	return 3;
}

int send_ttl(int interface, char *msg, struct ether_header *eth, struct iphdr *first_ip, struct iphdr *last_ip, char *data)
{
	//icmp creation
	struct icmphdr *icmp = calloc(1, sizeof(struct icmphdr));
	icmp->type = 11;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->checksum = checksum((uint16_t *)icmp, sizeof(struct iphdr) + sizeof(struct icmphdr) + 8);


	//new packet
	char *new_buff = malloc(sizeof(struct icmphdr) + sizeof(struct iphdr) * 2 + sizeof(struct ether_header) + 8);
	memcpy(new_buff, eth, sizeof(struct ether_header));
	memcpy(new_buff + sizeof(struct ether_header), first_ip, sizeof(struct iphdr));
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header), icmp, sizeof(struct icmphdr));
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr), last_ip, sizeof(struct iphdr)); 
	memcpy(new_buff + sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr) * 2, data, 8);
	send_to_link(interface, new_buff, sizeof(struct icmphdr) + sizeof(struct iphdr) * 2 + sizeof(struct ether_header) + 8);
	return 11;
}

int send_echo(int interface, char *buf, size_t len) {
	puts("echo\n");
	//icmp creation
	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr1 = (struct iphdr *)(buf + sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
	get_interface_mac(interface, eth_hdr->ether_shost);

	ip_hdr1->daddr = ip_hdr1->saddr;
	ip_hdr1->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr1->check = 0;
	ip_hdr1->check = htons(checksum((uint16_t *)ip_hdr1, sizeof(struct iphdr)));

	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	send_to_link(interface, buf, len);

	return 0;
}

int send_icmp(char *msg, char *buf, int interface, struct ether_header *ether_header, struct iphdr *ip_hdr)
{
	//ether_addres
	memcpy(ether_header->ether_dhost, ether_header->ether_shost, 6);
	get_interface_mac(interface, ether_header->ether_shost);

	//get first 8 bytes
	char *first8 = malloc(sizeof(char) * 8);
	memcpy(first8, buf + sizeof(struct iphdr) + sizeof(struct ether_header), 8);

	//modify first ip for icmp packet
	struct iphdr *first_ip = malloc(sizeof(struct iphdr));
	first_ip->tos = 0;
	first_ip->frag_off = 0;
	first_ip->version = 4;
	first_ip->ihl = 5;
	first_ip->id = 1;
	first_ip->check = 0;
	first_ip->protocol = 1;
	first_ip->tot_len = sizeof(struct iphdr) * 2 + 8 + sizeof(struct icmphdr);
	first_ip->daddr = ip_hdr->saddr;
	first_ip->saddr = inet_addr(get_interface_ip(interface));
	first_ip->check = checksum((uint16_t *)first_ip, sizeof(struct iphdr));

	//send
	if (strcmp(msg, "No route") == 0)
		return send_no_route(interface, msg, ether_header, first_ip, ip_hdr, first8);
	if (strcmp(msg, "Time to leave") == 0)
		return send_ttl(interface, msg, ether_header, first_ip, ip_hdr, first8);
	return -1;
}

int main(int argc, char *argv[])
{

	// Do not modify this line
	init(argc - 2, argv + 2);

	char buf[MAX_PACKET_LEN];
	rtable = malloc(sizeof(struct route_table_entry) * 80000);
	DIE(rtable == NULL, "memory");
	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), comp_function);
	arp_table = malloc(sizeof(struct  arp_table_entry) * 50);
	DIE(arp_table == NULL, "memory");
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
		if (ip_hdr->protocol == 1) {
			struct icmphdr *icmphdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
			if (icmphdr->type == 8 && ip_hdr->daddr == inet_addr(get_interface_ip(interface))) {
				printf("proto\n");
				icmphdr->type = 0;
				send_echo(interface, buf, len);
				continue;
			}
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
			int rc = send_icmp("No route", buf, interface, eth_hdr, ip_hdr);
			DIE( rc == -1, "Unrecognized message");
			continue;
		}
		printf("%d\n", 1);
		if (ip_hdr->ttl > 1) {
			ip_hdr->ttl--;
		} else {
			int rc = send_icmp("Time to leave", buf, interface, eth_hdr, ip_hdr);
			DIE( rc == -1, "Unrecognized message");
			continue;
		}
		ip_hdr->check = 0;
		check =  checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
		ip_hdr->check = htons(check);
		uint8_t add_mac[6];
		struct arp_table_entry *mac1 = get_mac_entry(best->next_hop);
		if (!mac1)
			continue;
		get_interface_mac(interface, add_mac);
		memcpy(eth_hdr->ether_dhost, mac1->mac, sizeof(mac1->mac));
		memcpy(eth_hdr->ether_shost, add_mac, sizeof(add_mac));
		send_to_link(best->interface, buf, len);
	}
}
