#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
//#include <netinet/ip_icmp.h> // Include for ICMP header definition
#include <arpa/inet.h>

#include "myheader.h"

// Function declaration for checksum calculation
unsigned short in_cksum(unsigned short *buf, int length){
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
   sum += (sum >> 16);                  // add carry
   return (unsigned short)(~sum);
};

void send_raw_ip_packet(struct ipheader* ip) {
    struct sockaddr_in dest_info;
    //struct packet_mreq enable;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Check for socket creation errors
    if (sock < 0) {
        printf("socket creation failed");
        return;
    }

    // Step 2: Set socket option.
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)) < 0) {
        printf("setsockopt failed");
        close(sock);
        return;
    }

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    ssize_t bytes_sent = sendto(sock, ip, ntohs(ip->iph_len), 0,
                                (struct sockaddr *)&dest_info, sizeof(dest_info));

    // Check for sendto errors
    if (bytes_sent < 0) {
        perror("sendto failed");
    }

    close(sock);
}

int main() {
   char buffer[1500];

   memset(buffer, 0, 1500);

   struct icmpheader *icmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
   icmp->_icmp_type = 8; // Set ICMP type to echo request (ping)
   icmp->_icmp_code = 0;
   icmp->_icmp_chksum = 0;
   icmp->_icmp_id = getpid(); // Use process ID as ICMP identifier
   icmp->_icmp_seq = 0; // Initialize sequence number (adjust as needed)


   // Calculate ICMP checksum
   icmp->_icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));

   struct ipheader *ip = (struct ipheader *)buffer;
   ip->iph_ver = 4;
   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");
   ip->iph_destip.s_addr = inet_addr("10.9.0.6");
   ip->iph_protocol = IPPROTO_ICMP;
   ip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

   printf("ICMP type: %u\n", icmp->_icmp_type);
   printf("ICMP code: %u\n", icmp->_icmp_code);
   printf("ICMP checksum: %u\n", icmp->_icmp_chksum);

   send_raw_ip_packet(ip);

   return 0;
}

