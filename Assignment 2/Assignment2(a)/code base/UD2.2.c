#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h> // Include for struct udphdr
#include <arpa/inet.h>

void send_raw_ip_packet(char *packet, int packet_size) {
    struct sockaddr_in dest_info;
    int enable = 1;
    
    // Step 1: Create a raw network socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Step 2: Set Socket option
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        perror("setsockopt");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Step 3: Provide destination information
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr.s_addr = inet_addr("10.0.2.6"); // Destination IP address
    
    // Step 4: Send the packet out
    if (sendto(sock, packet, packet_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info)) < 0) {
        perror("sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }
    
    close(sock);
}

int main() {
    int mtu = 1500;
    char buffer[mtu];
    memset(buffer, 0, mtu);

    // Define UDP header structure
    struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ip));
    
    // Construct the UDP payload
    char *data = buffer + sizeof(struct ip) + sizeof(struct udphdr);
    char *msg = "DORDOR!";
    int data_len = strlen(msg);
    memcpy(data, msg, data_len);

    // Construct the UDP header
    udp->uh_sport = htons(9190); // Source port
    udp->uh_dport = htons(9090); // Destination port
    udp->uh_ulen = htons(sizeof(struct udphdr) + data_len); // UDP length
    udp->uh_sum = 0; // UDP checksum (optional)

    // Define IP header structure
    struct ip *ip = (struct ip *)buffer;

    // Construct the IP header
    ip->ip_v = 4; // IP version
    ip->ip_hl = 5; // IP header length (in 32-bit words)
    ip->ip_ttl = 20; // Time to Live
    ip->ip_p = IPPROTO_UDP; // Protocol (UDP)
    ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr) + data_len); // IP Packet length
    ip->ip_src.s_addr = inet_addr("1.2.3.4"); // Source IP address
    ip->ip_dst.s_addr = inet_addr("10.9.0.6"); // Destination IP address
    
    // Send the raw IP packet
    send_raw_ip_packet(buffer, ntohs(ip->ip_len));
    
    return 0;
}

