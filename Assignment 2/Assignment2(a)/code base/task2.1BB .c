#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;

    // Check if the Ethernet type indicates an IPv4 packet
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Check if the protocol is TCP
        if (ip_header->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header->ip_hl * 4);

            // Check if the destination port is in the specified range
            if (ntohs(tcp_header->th_dport) >= 10 && ntohs(tcp_header->th_dport) <= 100) {
                printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
                printf("Destination Port: %d\n", ntohs(tcp_header->th_dport));
                printf("Protocol: TCP\n");
                return;
            }
        }
    }
    printf("Not a TCP packet with destination port in the range from 10 to 100\n");
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp dst portrange 10-100"; // Filter expression for TCP packets with destination port in the specified range
    bpf_u_int32 net, mask;

    // Open live pcap session on NIC with name br-412e2aa52fa6
    handle = pcap_open_live("br-412e2aa52fa6", BUFSIZ, 1, 1000, errbuf);

    // Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   // Close the handle
    return 0;
}














