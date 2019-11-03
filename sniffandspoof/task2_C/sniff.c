#include <pcap.h>
#include <stdio.h>
#include "header.h"
#include <string.h>
#include <arpa/inet.h>
void got_packet(u_char * args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethheader *eth = (struct ethheader *)packet;
        struct sniff_ip *ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);
	//printf("Ip src:%s,  Ip dst:%s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
    	
	// TCP
	u_int size_ip = IP_HL(ip)<<2;
	const struct sniff_tcp *tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	u_int size_tcp = TH_OFF(tcp)*4;
	const char *playload = (u_char *)(packet+SIZE_ETHERNET + size_ip + size_tcp );
	if(strlen(playload) != 0) {
		printf("%s",playload);
	}
}
int main()
{
	pcap_t * handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	//char filter_exp[] = "ip proto icmp";
	//char filter_exp[] = "icmp && host 10.0.2.129 && host 120.78.209.0";
	char filter_exp[] = "tcp port 23";
	bpf_u_int32 net;
	handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	pcap_loop(handle, -1, got_packet, NULL);
	pcap_close(handle); //Close the handle
	return 0;
}

