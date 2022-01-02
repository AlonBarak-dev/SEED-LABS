#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h> // for open
#include <unistd.h> // for close
#include "headers.h"


void send_packet(struct ipheader* ip) {
    /*
        this method is from the model.
        we used it to send packet throght a raw socket.
    */
    struct sockaddr_in dst;
	int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dst, sizeof(dst));
    close(sock);
}


void send_echo_reply(ipheader * ip) {
    /*
        this method is from the model.
    */
  int ip_header_len = ip->iph_ihl * 4;
  const char buffer[1024];

  // make a copy from original packet to buffer (faked packet)
  memset((char*)buffer, 0, 1024);
  memcpy((char*)buffer, ip, ntohs(ip->iph_len));
  ipheader* newip = (ipheader*)buffer;
  icmpheader* newicmp = (icmpheader*)(buffer + ip_header_len);

  // Construct IP: swap src and dest in faked ICMP packet
  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->iph_sourceip;
  newip->iph_ttl = 64;

  // Fill in all the needed ICMP header information.
  // ICMP Type: 8 is request, 0 is reply.
  newicmp->icmp_type = 0;

  send_packet (newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,  const u_char *packet) {
    /*
        this method is from the model.
    */
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    ipheader * ip = (ipheader *)(packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));   

    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");      // send reply only for ICMP packets
			send_echo_reply(ip);
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
}




int main(){
    
    pcap_t *handle;


    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf;
    
    char filter_exp[] = "icmp[icmptype] = 8";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, error_buffer); 
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &bpf, filter_exp, 0, net);      
    pcap_setfilter(handle, &bpf);                             
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                



    pcap_close(handle);   //Close the handle 
    return 0;
}

