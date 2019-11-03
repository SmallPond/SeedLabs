#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include "header.h"

#define IP_SRC "10.0.2.128"
#define IP_DST "10.0.2.129"

unsigned short checksum(unsigned short *buffer, int size){
    int checksum = 0;
    while(size>1){
        checksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if(size){
        checksum += *(unsigned char*)buffer;
    }
    checksum = (checksum>>16) + (checksum & 0xffff);
    checksum += (checksum>>16);
    return (unsigned short)(~checksum);
}

int main(){
    int sd;
    int len = 0;
    struct sockaddr_in sin;
    char buffer[1024];

    sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(sd < 0) {
        perror("socket() error"); 
        exit(-1); 
    }
    sin.sin_family = AF_INET;

    struct sniff_ip *ip = (struct sniff_ip *) buffer;
    struct sniff_icmp *icmp = (struct sniff_icmp *)(buffer + sizeof(struct sniff_ip));
    struct in_addr *ip_src = (struct in_addr *)malloc(sizeof(struct in_addr));
    struct in_addr *ip_dst = (struct in_addr *)malloc(sizeof(struct in_addr));
    inet_aton(IP_SRC,ip_src);
    inet_aton(IP_DST,ip_dst);
    
    len += sizeof(struct sniff_icmp);
    icmp->icmp_type = 8;
    icmp->icmp_code = 0;
    icmp->icmp_chksum = 0;
    icmp->icmp_id = htons(0x1234); // A real ping should apply the last few bits of pid here
    icmp->icmp_seq = htons(1);
    icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct sniff_icmp));  
    
    len += sizeof(struct sniff_ip);
    // ip->ip_ihl = 5; // header in 4 bytes
    ip->ip_vhl = 4<<4 | 5;
    ip->ip_tos = 0;
    ip->ip_len = htons(10); // header and data in bytes
    // ip->ip_ident = htons(0x1000);
    ip->ip_off = 0;
    ip->ip_ttl = 64;
    ip->ip_p = ICMP_PROTOCOL_NUM;
    ip->ip_src = *ip_src;
    ip->ip_dst = *ip_dst;

    if(sendto(sd, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        printf("sendto() error"); 
	exit(-1); 
    }
}
