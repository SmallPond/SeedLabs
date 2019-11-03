#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <pcap.h>
#include "header.h"

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


// pay attention to the ip_src and ip_dst
int spoof(int sock, struct in_addr ip_src, struct in_addr ip_dst, struct spoof_icmp * r_icmp)
{
	char buffer[1024];
	struct sockaddr_in sin;
	int len = 0;

	sin.sin_family = AF_INET;
	struct sniff_ip *ip = (struct sniff_ip *) buffer;
	struct spoof_icmp *icmp = (struct spoof_icmp *)(buffer + sizeof(struct sniff_ip));

	len += sizeof(struct spoof_icmp);
	icmp->icmp_type = 0;
	icmp->icmp_code = 0;
	icmp->icmp_chksum = 0;
	icmp->icmp_id = r_icmp->icmp_id; // A real ping should apply the last few bits of pid here
	icmp->icmp_seq = r_icmp->icmp_seq;
	icmp->icmp_chksum = checksum((unsigned short *)icmp, sizeof(struct spoof_icmp));  
	for(int i = 0; i < ICMP_DATA_LENGTH; i++){
		icmp->icmp_data[i] = r_icmp->icmp_data[i];
    	}
	len += sizeof(struct sniff_ip);
	ip->ip_vhl = 4<<4 | 5;
	ip->ip_tos = 0;
	// ip->ip_len = htons(10); // header and data in bytes
	ip->ip_off = 0;
	ip->ip_ttl = 64;
	ip->ip_p = ICMP_PROTOCOL_NUM;
	ip->ip_src = ip_dst;
	ip->ip_dst = ip_src;

	if(sendto(sock, buffer, len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
		printf("sendto() error"); 
		exit(-1); 
	}
}


void got_packet(u_char * args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
        struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	printf("Ip src:%s,  Ip dst:%s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
	// ICMP 
	u_int size_ip = IP_HL(ip)<<2;
	struct spoof_icmp *icmp = (struct spoof_icmp *)(packet + SIZE_ETHERNET + size_ip);
		
	int sock = (int)args;
	
    	spoof(sock, ip->ip_src, ip->ip_dst, icmp);
}





int main(){

	int sock;
	pcap_t * handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	
	

	bpf_u_int32 net;
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if(sock < 0) {
		perror("socket() error"); 
		exit(-1); 
	}

	char filter_exp[] = "icmp && ip src 10.0.2.129";

	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	pcap_loop(handle, -1, got_packet, (u_char*) sock);
	
	pcap_close(handle); //Close the handle
}
