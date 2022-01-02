#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include "headers.h"


void send_packet(ipheader *ip){
    struct sockaddr_in dst;
    int enable = 1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);  // creating a raw socket
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));  // setting the socket options 

    /**
     * giving the sock address struct some info about the destination of the packet (from ip header)
     */
    dst.sin_family = AF_INET;
    dst.sin_addr = ip->iph_destip;

    sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr*)&dst, sizeof(dst));       //sending the packet with its new attributs

    close(sock);    // closing the socket when done
}

void main(){

    // creating a buffer and reset its chars 0.
    int length = 2000;
    char buf[length];
    memset(buf, 0, length);

    // creating a UDP packet 
    u_header* udp_H = (u_header*)(buf + sizeof(ipheader));
    char* buf2 = buf + sizeof(u_header) + sizeof(ipheader);
    char* data = "SPOOF WORKED!";
    memcpy(buf2, data, strlen(data));

    udp_H->udp_sport = htons(9190);
    udp_H->udp_dport = htons(9090);
    size_t udp_len = sizeof(u_header) + strlen(data);
    udp_H->udp_ulen = htons(udp_len);
    udp_H->udp_sum = 0;
    // creating an ip header and setting its attributes
    ipheader* ip = (ipheader *)buf;
    ip->iph_ihl = 5;
    ip->iph_ver = 4;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr("1.2.3.4"); // random IP 
    ip->iph_destip.s_addr = inet_addr("10.0.2.15");     // our VM IP
    ip->iph_protocol = IPPROTO_UDP;
    ip->iph_len = htons(sizeof(ipheader) + strlen(data) + sizeof(u_header));

    send_packet(ip);    // sending the packet via the auxiliary method -send_packet- 


}