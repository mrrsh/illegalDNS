#include	<stdio.h>
#include	<string.h>
#include	<unistd.h>
#include	<sys/ioctl.h>
#include	<arpa/inet.h>
#include	<sys/socket.h>
#include	<linux/if.h>
#include	<net/ethernet.h>
#include	<netpacket/packet.h>
#include	<netinet/if_ether.h>
#include	<netinet/ip.h>
#include	<netinet/ip6.h>
#include	<netinet/ip_icmp.h>
#include	<netinet/icmp6.h>
#include	<netinet/tcp.h>
#include	<netinet/udp.h>
#include	"checksum.h"
#include	"print.h"

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6  0x86dd
#endif

#define DNS_port 53
//#define MAX_PAYLOAD 1059
#define MAX_PAYLOAD 1119
int flags = 0;
struct  dnshdr{
	u_int16_t id;
	u_int16_t flags;
	u_int16_t qdcount;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
};
struct dnspacket_test{
	struct dnshdr hdr;
	char payload[MAX_PAYLOAD];
};
int AnalyzeArp(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct ether_arp	*arp;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_arp)){
		fprintf(stderr,"lest(%d)<sizeof(struct iphdr)\n",lest);
		return(-1);
	}
	arp=(struct ether_arp *)ptr;
	ptr+=sizeof(struct ether_arp);
	lest-=sizeof(struct ether_arp);

	//PrintArp(arp,stdout);

	return(0);
}

int AnalyzeIcmp(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct icmp	*icmp;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct icmp)){
		fprintf(stderr,"lest(%d)<sizeof(struct icmp)\n",lest);
		return(-1);
	}
	icmp=(struct icmp *)ptr;
	ptr+=sizeof(struct icmp);
	lest-=sizeof(struct icmp);

	PrintIcmp(icmp,stdout);

	return(0);
}

int AnalyzeIcmp6(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct icmp6_hdr	*icmp6;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct icmp6_hdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct icmp6_hdr)\n",lest);
		return(-1);
	}
	icmp6=(struct icmp6_hdr *)ptr;
	ptr+=sizeof(struct icmp6_hdr);
	lest-=sizeof(struct icmp6_hdr);

	PrintIcmp6(icmp6,stdout);

	return(0);
}

int AnalyzeTcp(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct tcphdr	*tcphdr;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct tcphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct tcphdr)\n",lest);
		return(-1);
	}

	tcphdr=(struct tcphdr *)ptr;
	ptr+=sizeof(struct tcphdr);
	lest-=sizeof(struct tcphdr);

	PrintTcp(tcphdr,stdout);

	return(0);
}
int GenerateLabel(char *payload){
	int i;
	char s[64];

	s[0] = 63;
	for(i = 1; i < 64; i++){
		s[i] = 'a';
	}
	for(i = 0; i < 16; i++){
		memcpy(payload+i*64,s,64);
	}
	return 0;
}
int SendDNSPacket(u_int16_t DNSid,u_int16_t dest){
	int sock;
	struct sockaddr_in addr,srcaddr;
	int disable = 1;
	//char qd[] = "\x03\x77\x77\x77\x05\x61\x70\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
	char qd[] = "\x3f\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x05\x61\x70\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
	char qd_aaaa[] = "\x3f\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x77\x05\x61\x70\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01";
	//char qd_aaaa[] = "\x03\x77\x77\x77\x05\x61\x70\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x1c\x00\x01";
	//char an_[] = "\x00\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xd8\x3a\xc5\xa3";
	char an_[] = "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x0a\x00\x04\xd8\x3a\xc5\xa3";
	
	//パケット生成
	fprintf(stdout,"TEST DNSPacket ID is %X\n",ntohs(DNSid));
	struct dnshdr sendhdr;
	struct dnspacket_test send;
	sendhdr.id = DNSid;
	sendhdr.flags = ntohs(33024);
	sendhdr.qdcount = ntohs(1);
	sendhdr.ancount = ntohs(1);
	sendhdr.nscount = 0;
	sendhdr.arcount = 0;
	send.hdr = sendhdr;
	if(flags == 0){
		memcpy(send.payload,qd,sizeof(qd));
		flags = 1;
	}
	else{
		memcpy(send.payload,qd_aaaa,sizeof(qd_aaaa));
		flags = 0;
	}
	GenerateLabel(send.payload+sizeof(qd)-1);
	memcpy(send.payload+1024+sizeof(qd)-1,an_,sizeof(an_));
	
	//ソケット作成、設定
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, (void*)&disable, sizeof(disable)) < 0) {
		perror("setsockopt failed");
	}
	//送信先の設定
	addr.sin_family = AF_INET;
	printf("%u\n",ntohs(dest));
	addr.sin_port = dest;
	addr.sin_addr.s_addr = inet_addr("192.168.11.15");
	//送信元の設定
	srcaddr.sin_family = AF_INET;
    srcaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    srcaddr.sin_port = htons(53);
	//送信
	if (bind(sock, (struct sockaddr *) &srcaddr, sizeof(srcaddr)) < 0) {
        perror("bind");
        return -1;
    }
	if(send.payload[MAX_PAYLOAD-1] != '\x00')
		sendto(sock, &send, sizeof(struct dnspacket_test), 0, (struct sockaddr *)&addr, sizeof(addr));
	else
		sendto(sock, &send, sizeof(struct dnspacket_test)-1, 0, (struct sockaddr *)&addr, sizeof(addr));
	printf("OK\n");
	close(sock);
	return 0;
}

int AnalyzeDNS(u_char *data, int size,u_int16_t dest){
	u_char *ptr;
	int lest;
	struct dnshdr *hdr;
	ptr = data;
	lest = size;
	if(lest<sizeof(struct dnshdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct dnshdr)\n",lest);
		return(-1);
	}
	hdr = (struct dnshdr *)ptr;
	ptr += sizeof(struct dnshdr);
	lest -= sizeof(struct dnshdr);
	
	fprintf(stdout,"DNSPacket ID is %X\n",ntohs(hdr->id));
	SendDNSPacket(hdr->id,dest);
	return(0);
}

int AnalyzeUdp(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct udphdr	*udphdr;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct udphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct udphdr)\n",lest);
		return(-1);
	}

	udphdr=(struct udphdr *)ptr;
	ptr+=sizeof(struct udphdr);
	lest-=sizeof(struct udphdr);

	if(ntohs(udphdr->dest) == DNS_port){
		AnalyzeDNS(ptr,lest,udphdr->source);
	}
	//PrintUdp(udphdr,stdout);	

	return(0);
}

int AnalyzeIp(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct iphdr	*iphdr;
u_char	*option;
int	optionLen,len;
unsigned short  sum;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct iphdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct iphdr)\n",lest);
		return(-1);
	}
	iphdr=(struct iphdr *)ptr;
	ptr+=sizeof(struct iphdr);
	lest-=sizeof(struct iphdr);

	optionLen=iphdr->ihl*4-sizeof(struct iphdr);
	if(optionLen>0){
		if(optionLen>=1500){
			fprintf(stderr,"IP optionLen(%d):too big\n",optionLen);
			return(-1);
		}
		option=ptr;
		ptr+=optionLen;
		lest-=optionLen;
	}

	if(checkIPchecksum(iphdr,option,optionLen)==0){
		fprintf(stderr,"bad ip checksum\n");
		return(-1);
	}

	//PrintIpHeader(iphdr,option,optionLen,stdout);


	if(iphdr->protocol==IPPROTO_UDP){
		struct udphdr	*udphdr;
		udphdr=(struct udphdr *)ptr;
		len=ntohs(iphdr->tot_len)-iphdr->ihl*4;
		if(udphdr->check!=0&&checkIPDATAchecksum(iphdr,ptr,len)==0){
			fprintf(stderr,"bad udp checksum\n");
			PrintIpHeader(iphdr,option,optionLen,stdout);
			return(-1);
		}
		AnalyzeUdp(ptr,lest);
	}

	return(0);
}

int AnalyzeIpv6(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct ip6_hdr	*ip6;
int	len;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ip6_hdr)){
		fprintf(stderr,"lest(%d)<sizeof(struct ip6_hdr)\n",lest);
		return(-1);
	}
	ip6=(struct ip6_hdr *)ptr;
	ptr+=sizeof(struct ip6_hdr);
	lest-=sizeof(struct ip6_hdr);

	//PrintIp6Header(ip6,stdout);

	if(ip6->ip6_nxt==IPPROTO_UDP){
		len=ntohs(ip6->ip6_plen);
		if(checkIP6DATAchecksum(ip6,ptr,len)==0){
			fprintf(stderr,"bad udp6 checksum\n");
			return(-1);
		}
		AnalyzeUdp(ptr,lest);
	}

	return(0);
}

int AnalyzePacket(u_char *data,int size)
{
u_char	*ptr;
int	lest;
struct ether_header	*eh;

	ptr=data;
	lest=size;

	if(lest<sizeof(struct ether_header)){
		fprintf(stderr,"lest(%d)<sizeof(struct ether_header)\n",lest);
		return(-1);
	}
	eh=(struct ether_header *)ptr;
	ptr+=sizeof(struct ether_header);
	lest-=sizeof(struct ether_header);

	if(ntohs(eh->ether_type)==ETHERTYPE_ARP){
		//fprintf(stderr,"Packet[%dbytes]\n",size);
		//PrintEtherHeader(eh,stdout);
		AnalyzeArp(ptr,lest);
	}
	else if(ntohs(eh->ether_type)==ETHERTYPE_IP){
		//fprintf(stderr,"Packet[%dbytes]\n",size);
		//PrintEtherHeader(eh,stdout);
		AnalyzeIp(ptr,lest);
	}
	else if(ntohs(eh->ether_type)==ETHERTYPE_IPV6){
		//fprintf(stderr,"Packet[%dbytes]\n",size);
		//PrintEtherHeader(eh,stdout);
		AnalyzeIpv6(ptr,lest);
	}

	return(0);
}


