#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "headers.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
        struct ipheader * ip = (struct ipheader *)(packet + sizeof(struct ethheader)); 
        printf("Captured Packet: \n");
        printf("Source: %s   \n", inet_ntoa(ip->iph_sourceip));  
        printf("Destination: %s\n", inet_ntoa(ip->iph_destip));   
    }
}

int main() {
  pcap_t *handle;
  char error_buffer[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;
  char filter[] = "ip proto icmp";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 0, 1000, error_buffer); 

  // Step 2: Compile filter into BPF psuedo-code
  pcap_compile(handle, &bpf, filter, 0, net);              
  pcap_setfilter(handle, &bpf);                                

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}