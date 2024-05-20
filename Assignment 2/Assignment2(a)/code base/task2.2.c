#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PACKET_SIZE 4096
#define ICMP_ECHO_REPLY 0

// Simple checksum function
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;

    if (len == 1)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}

int main(int argc, char *argv[]) {
    int sockfd;
    char packet[PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *) packet;
    struct icmphdr *icmph = (struct icmphdr *) (packet + sizeof(struct iphdr));
    struct sockaddr_in sin;
    int one = 1;
    const int *val = &one;

    // Create raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("socket() error");
        exit(EXIT_FAILURE);
    }

    // IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    iph->id = htons(12345);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0; // Set to 0 before calculating checksum
    iph->saddr = inet_addr("1.2.3.4"); // Spoofed source IP
    iph->daddr = inet_addr("10.9.0.5"); // Destination IP

    // ICMP header
    icmph->type = 8;
    icmph->code = 0;
    icmph->un.echo.id = 0;
    icmph->un.echo.sequence = 0;
    icmph->checksum = 0; // Set to 0 before calculating checksum

    // Calculate IP header checksum
    iph->check = checksum((unsigned short *)packet, iph->tot_len);

    // Calculate ICMP checksum
    icmph->checksum = checksum((unsigned short *)(packet + sizeof(struct iphdr)), sizeof(struct icmphdr));

    // Set socket options
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    // Fill in the destination sockaddr
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = iph->daddr;

    // Send the packet
    if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto() error");
        exit(EXIT_FAILURE);
    }

    close(sockfd);

    return 0;
}

