#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
printf("Got a packet\n");
}

int main()
{
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "icmp";
bpf_u_int32 net;

handle = pcap_open_live("br-412e2aa52fa6", BUFSIZ, 1, 1000, errbuf);

pcap_compile(handle, &fp, filter_exp, 0, net);
if (pcap_setfilter(handle, &fp) !=0) {
pcap_perror(handle, "Error:");
exit(EXIT_FAILURE);
}

pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle);
return 0;

}
