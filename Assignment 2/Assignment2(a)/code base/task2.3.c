#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>

// Structure to hold source and destination IP addresses
struct IpAddresses {
    char source[INET_ADDRSTRLEN];
    char destination[INET_ADDRSTRLEN];
};

// Function to spoof an ICMP echo reply packet
void spoof_icmp_echo_reply(const u_char *packet, int packet_len) {
    // Extract Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Extract IP header
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Calculate the new IP total length
    int new_ip_len = ntohs(ip_header->ip_len);

    // Allocate memory for the spoofed packet
    u_char *spoofed_packet = (u_char *)malloc(packet_len);

    // Copy the original packet to the spoofed packet
    memcpy(spoofed_packet, packet, packet_len);

    // Modify the IP header to swap source and destination
    struct ip *new_ip_header = (struct ip *)(spoofed_packet + sizeof(struct ether_header));
    struct in_addr temp_addr = new_ip_header->ip_src;
    new_ip_header->ip_src = new_ip_header->ip_dst;
    new_ip_header->ip_dst = temp_addr;
    new_ip_header->ip_sum = 0; // Recalculate IP checksum later

    // Modify the ICMP type to echo reply
    u_char *icmp_payload = spoofed_packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
    icmp_payload[0] = 0; // ICMP type (echo reply)

    // Recalculate IP checksum
    int sum = 0;
    for (int i = 0; i < (new_ip_len / 2); i++) {
        sum += *(unsigned short *)(spoofed_packet + sizeof(struct ether_header) + i * 2);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    new_ip_header->ip_sum = ~sum;

    // Send the spoofed packet
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live("br-70a143fa7795", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_sendpacket(handle, spoofed_packet, packet_len) != 0) {
        fprintf(stderr, "Error sending packet: %s\n", pcap_geterr(handle));
    }
    pcap_close(handle);

    free(spoofed_packet);
}

// Function to process captured packets and extract source and destination IP addresses
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_count = 0; // Count packets
    packet_count++;

    // Extract Ethernet header
    struct ether_header *eth_header = (struct ether_header *)packet;
    uint16_t ether_type = ntohs(eth_header->ether_type);

    // Check if the packet is IPv4
    if (ether_type == ETHERTYPE_IP) {
        // Extract IP header
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // Copy source and destination IP addresses into the IpAddresses structure
        struct IpAddresses addresses;
        inet_ntop(AF_INET, &(ip_header->ip_src), addresses.source, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), addresses.destination, INET_ADDRSTRLEN);

        // Print source and destination IP addresses
        printf("PACKET no. %d: SOURCE IP: %s\n", packet_count, addresses.source);
        printf("PACKET no. %d: DESTINATION IP: %s\n", packet_count, addresses.destination);

        // Check if it's an ICMP echo request (type 8)
        if (ip_header->ip_p == IPPROTO_ICMP) {
            //u_char *icmp_payload = packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4);
            u_char *icmp_payload = (u_char *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));

            if (icmp_payload[0] == 8) {
                printf("Received ICMP Echo Request (type 8)\n");
                printf("Spoofing ICMP Echo Reply...\n");
                spoof_icmp_echo_reply(packet, header->caplen);
            }
        }
    } else {
        printf("Packet %d: Not an IPv4 packet\n", packet_count);
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    // Open live pcap session on NIC with name "eth0"
    handle = pcap_open_live("br-70a143fa7795", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device eth0: %s\n", errbuf);
        return 1;
    }

    // Compile filter_exp into BPF psuedo-code
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    // Close the handle
    pcap_close(handle);

    return 0;
}

