#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "headers.h"

unsigned short in_cksum (unsigned short *buf, int length) {

    /**
     * this method is from the model.
     * it calculate the checksum of a given packet.
     * we used it in our code, hope it is fine :)
     * */
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
}

void send_packet(struct ipheader* ip) {
    /*
        this method is from the model.
        we used it to send packet throght a raw socket.
    */
    struct sockaddr_in dest_info;
	int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

int main() {
   // creating a buffer and reseting its chars to zero
   char buf[2000];
   memset(buf, 0, strlen(buf));

   icmpheader *icmp = (icmpheader *)(buf + sizeof(ipheader));
   icmp->icmp_type = 8; 
   icmp->icmp_chksum = 0;
   icmp->icmp_chksum = in_cksum((unsigned short *)icmp,sizeof(struct icmpheader));  // calculating the packet checksum using the model's method.


   // creating a IP packet and restarting its attributes
   struct ipheader *ip = (ipheader *) buf;

   ip->iph_ihl = 5;
   ip->iph_ttl = 20;
   ip->iph_ver = 4;


   ip->iph_sourceip.s_addr = inet_addr("1.2.3.4");  // random IP address (fake)
   ip->iph_destip.s_addr = inet_addr("10.0.2.15");  // VM IP address (real)

   
   ip->iph_protocol = IPPROTO_ICMP; // setting the protocol of the packet as ICMP protocol
   ip->iph_len = htons(sizeof(ipheader) + sizeof(icmpheader));

   // printing the packet sequance and type
   printf("SEQ = %hu ", icmp->icmp_seq);
   printf("TYPE = %u \n", icmp->icmp_type);

   // eventually, sending the spoofed packet away
   send_packet(ip);

   return 0;
}