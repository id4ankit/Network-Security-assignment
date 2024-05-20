#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ether_header *eth_header = (struct ether_header *)packet;
    // Check if the Ethernet type indicates an IPv4 packet
    	if (ntohs(eth_header->ether_type) == 0x0800) {
    
	struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
	
        // Check if the protocol is ICMP
        if (ip_header->ip_p == IPPROTO_ICMP) {
		printf(" SOURCE IP: %s\n",inet_ntoa(ip_header->ip_src));
		printf(" DESTINATION IP: %s\n",inet_ntoa(ip_header->ip_dst));
            	printf("Protocol: ICMP\n");
            	return;
        }
    }
    printf("Not an ICMP packet\n");
}
//ip->iph_protocol== IPPROTO_ICMP:

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip"; // filter expression to capture all IP packets
    bpf_u_int32 net, mask;
    //open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("br-412e2aa52fa6", BUFSIZ, 1, 1000, errbuf);

    //compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }
    //capture packets
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);   //Close the handle
    return 0;
}
