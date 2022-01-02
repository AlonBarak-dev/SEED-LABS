#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "headers.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  ethheader *eth = (ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { 
    ipheader * ip = (ipheader *)(packet + sizeof(ethheader)); 

    // print the type of the protocol only if it is ICMP
    if (ip->iph_protocol == IPPROTO_TCP)
    {
        printf("Packet capture:     ");
        printf("Source: %s   ", inet_ntoa(ip->iph_sourceip));  
        printf("Destination: %s", inet_ntoa(ip->iph_destip));
        printf(" , Protocol: TCP\n");
        return;
    }
    else{
        return;
    }
  }
}

int main() {
  pcap_t *handle;
  char error_buffer[PCAP_ERRBUF_SIZE];
  struct bpf_program bpf;

  char filter[] = "proto TCP and dst portrange 10-100";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, error_buffer); 

  // Step 2: Compile filter into BPF psuedo-code
  pcap_compile(handle, &bpf, filter, 0, net);              
  pcap_setfilter(handle, &bpf);                                

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}