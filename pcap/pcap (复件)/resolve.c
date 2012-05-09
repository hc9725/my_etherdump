#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define arp 1
#define ip 2
#define tcp 3
#define udp 4
#define http 5
#define oicq 6
#define webqq 7
#define msnms 8

#pragma pack (1)
struct oicq_hdr{
    uint8_t flag;
    uint16_t version;
    uint16_t command;
    uint16_t seq;
    uint32_t data;
};//__attribute__((__packed__));
//typedef struct oicq_hdr _oicq_hdr;
static int other_num = 0;
static int oicq_num = 0;
static int tcp_num = 0;
static int udp_num = 0;
static int ip_num = 0;
static int arp_num = 0;
static int http_num = 0;
static int webqq_num = 0;
static int msnms_num = 0;

static long other_bytes = 0;
static long oicq_bytes = 0;
static long tcp_bytes = 0;
static long udp_bytes = 0;
static long ip_bytes = 0;
static long arp_bytes = 0;
static long http_bytes = 0;
static long webqq_bytes = 0;
static long msnms_bytes = 0;

ip_oicq head;
char srcip[16];
char desip[16];
int flag = 0;
static int num = 0;

void ethernet_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void arp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void ip_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void tcp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void udp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void oicq_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content);
void command_packet_callback(uint16_t command);//分析oicq不同的消息类型
void http_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,char *packet);
void msnms_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,char *packet);

void ethernet_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
    struct ethhdr *ethptr;
    struct iphdr *ipptr;
    unsigned char *mac;
    int i;
/*    for(i = 0; i < pcap_header->len; i++){
	printf("%02x ",packet_content[i]);
    }
    printf("\n\n\n");*/
    ethptr=(struct ethhdr *)packet_content;
    printf("\n----ethernet protocol(phydical layer)-----\n");
    for(i = 0; i < 14; i++)
	printf("%02x ",packet_content[i]);
    printf("\n");

    printf("MAC source Address:\n");
    mac=ethptr->h_source;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
    printf("MAC destination Address:\n");
    mac=ethptr->h_dest;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac,*(mac+1),*(mac+2),*(mac+3),*(mac+4),*(mac+5));
    printf("protocol:%04x\n",ntohs(ethptr->h_proto));
    switch(ntohs(ethptr->h_proto)) {
	case 0x0800:
	    printf("this is a IP protocol\n");
	    flag = ip;
	    ip_packet_callback(argument,pcap_header,packet_content);
	    break;
	case 0x0806:
	    printf("this is a ARP protocol\n");
	    flag = arp;
	    arp_packet_callback(argument,pcap_header,packet_content);
	    break;
	case 0x8035:
	    printf("this is a RARP protocol\n");
	    break;
	default:
	    break;
    }
}

void arp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
    arp_num++;
    int i = 14;
    arp_bytes += pcap_header->len;
    printf("------ARP Protocol-------\n");
}

void ip_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
     struct in_addr s,d;
     struct iphdr *ipptr;
     int i;
     ip_num++;
     ip_bytes += pcap_header->len;
     ipptr=(struct iphdr *)(packet_content+14);
     printf("-----IP Protocol (network layer)-----\n");
     for(i = 14; i < 34; i++)
	 printf("%02x ",packet_content[i]);
     printf("\n");

     printf("version:%d\n",ipptr->version);
     printf("header length:%d\n",ipptr->ihl*4);
     printf("tos:%d\n",ipptr->tos);
     printf("total length:%d\n",ntohs(ipptr->tot_len));
     printf("identification:%d\n",ntohs(ipptr->id));
     printf("offset:%d\n",ntohs((ipptr->frag_off&0x1fff)*8));
     printf("TTL:%d\n",ipptr->ttl);
     printf("checksum:%d\n",ntohs(ipptr->check));
     printf("protocol:%d\n",ipptr->protocol);
     s.s_addr=ipptr->saddr;
     d.s_addr=ipptr->daddr;
     printf("source address:%s\n",inet_ntoa(s));
     printf("destination address:%s\n",inet_ntoa(d));
     strcpy(srcip,inet_ntoa(s));
     strcpy(desip,inet_ntoa(d));
     switch(ipptr->protocol) {
	 case 6:
	     printf("This is tcp protocol\n");
	     flag = tcp;
	     tcp_packet_callback(argument,pcap_header,packet_content);
	     break;
	 case 1:
	     printf("This is icmp protocol\n");
	     break;
	 case 17:
	     printf("This is udp protocol\n");
	     flag = udp;
	     if(search_ip_list(head,srcip,desip) == 1){
		 printf("This is oicq protocol\n");
		 oicq_packet_callback(argument,pcap_header,packet_content);
	     }
	     else
		 udp_packet_callback(argument,pcap_header,packet_content);
	     break;
	 default:
	     break;
     }
}

void tcp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
     struct tcphdr *tcpptr=(struct tcphdr *)(packet_content+14+20);
     int i = 0;
     char packet[BUFSIZ],tmp[2],str[10];
     tcp_num++;
     tcp_bytes += pcap_header->len;
     printf("----tcp protocol-----\n");
     for(i = 34; i < 34+tcpptr->doff*4; i++)
	 printf("%02x ",packet_content[i]);
     printf("\n");
     printf("source port:%d\n",ntohs(tcpptr->source));
     printf("dest port:%d\n",ntohs(tcpptr->dest));
     printf("sequence number:%u\n",ntohl(tcpptr->seq));
     printf("acknowledgement number:%u\n",ntohl(tcpptr->ack_seq));
     printf("header length:%d\n",tcpptr->doff*4);
     printf("check sum:%d\n",ntohs(tcpptr->check));
     printf("window size:%d\n",ntohs(tcpptr->window));
     printf("urgent pointer:%d\n",ntohs(tcpptr->urg_ptr));
   
/*     for(i = 34+tcpptr->doff*4; i < pcap_header->len; i++){
	 printf("%c",packet_content[i]);
     }
     printf("\n");*/
     strcpy(packet,"\0");
     for(i = 34+tcpptr->doff*4; i < pcap_header->len; i++){
	 sprintf(tmp,"%c",packet_content[i]);
	 strcat(packet,tmp);
     }
//     printf("%s",packet);
     if(strstr(packet,"HTTP/1.1")&&strstr(packet,"\r\n\r\n")){
	 strncpy(str,packet,8);
	 str[8] = '\0';
	 if(strcmp(str,"HTTP/1.1") == 0)
	     printf("----this is http protocol(response message)-----\n");
	 else
	     printf("----this is http protocol(request message)-----\n");
	 flag = http;
	 http_packet_callback(argument,pcap_header,packet);
     }
     if(*packet != '\0' && (ntohs(tcpptr->source) == 0x0747 || ntohs(tcpptr->dest) == 0x0747)){
	 printf("----this is msnms protocol-----\n");
	 flag = msnms;
	 msnms_packet_callback(argument,pcap_header,packet);
     }

}

void udp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
     int i;
     udp_num++;
     udp_bytes += pcap_header->len;
     struct udphdr *udpptr = (struct udphdr *)(packet_content+14+20);
     printf("----udp protocol-----\n");
     for(i = 34; i < 42; i++)
	 printf("%02x ",packet_content[i]);
     printf("\n");
     printf("source port:%d\n",ntohs(udpptr->source));
     printf("dest port:%d\n",ntohs(udpptr->dest));
     printf("UDP length:%d\n",ntohs(udpptr->len));
     printf("check sum:%d\n",ntohs(udpptr->check));
     if(packet_content[i] != '\0') {
	 printf("flag:0x%02x\n",packet_content[i]);
	 switch(packet_content[i]){
	     case 0x02:
		 if(8000 == ntohs(udpptr->source) || 8000 == ntohs(udpptr->dest)){
		     printf("This is a oicq protocol\n");
		     flag = oicq;
		     oicq_packet_callback(argument,pcap_header,packet_content);
		 }
		 break;
	     default:
		 break;
	 }
     }
}


void oicq_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content){
    oicq_num++;
    oicq_bytes += pcap_header->len;
    ip_oicq tmp;
    struct oicq_hdr *oicqhdr = (struct oicq_hdr *)(packet_content+14+20+8);
    printf("-----oicq protocol-----\n");
    printf("flag:oicq packet(0x%02x)\n",oicqhdr->flag);
    printf("version: 0x%02x\n",ntohs(oicqhdr->version));
    command_packet_callback(oicqhdr->command);
    printf("sequence: %d\n",ntohs(oicqhdr->seq));
    printf("data (oicq number,if sender is client):%u\n",ntohl(oicqhdr->data));
    if(search_ip_list(head,srcip,desip) == 0){
	insert_ip_list(head,srcip,desip);
    }
}

void command_packet_callback(uint16_t command){
    switch(ntohs(command)){
	case 0x0002:
	    printf("command: heart message (%d)\n",ntohs(command)); break;
	case 0x0006:
	    printf("command: get user information broadcast (%d)\n",ntohs(command)); break;
	case 0x000d:
	    printf("command: set status (%d)\n",ntohs(command)); break;
	case 0x0016:
	    printf("command: send message (%d)\n",ntohs(command)); break;
	case 0x0017:
	    printf("command: receive message (%d)\n",ntohs(command)); break;										          case 0x001d: 
    	    printf("command: request key (%d)\n",ntohs(command)); 
	case 0x0022:
	    printf("command: log in (%d)\n",ntohs(command)); break;
	case 0x0026:													             
	    printf("command: get friend list (%d)\n",ntohs(command)); break;
	case 0x0027:
	    printf("command: get friend online (%d)\n",ntohs(command)); break;					
	case 0x0030:
	    printf("operation on group (%d)\n",ntohs(command)); break;
	case 0x003c:
	    printf("command: group name operation (%d)\n",ntohs(command)); break;
	case 0x003e:
	    printf("command: MEMO operation (%d)\n",ntohs(command)); break;
	case 0x0058:
	    printf("command: download group friend (%d)\n",ntohs(command)); break;
	case 0x0067:
	    printf("command: signature operation (%d)\n",ntohs(command)); break;
	case 0x0081:
	    printf("command: get status of friend (%d)\n",ntohs(command)); break;
	case 0x0062:
	    printf("command: request login (%d)\n",ntohs(command)); break;
	default:
	    break;	
    }
}

void http_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,char *packet){
 http_num++;
 http_bytes += pcap_header->len;
 char *tmp = packet;
 char *str;
 str = strstr(packet,"\r\n\r\n");
 while(str && str != tmp){
     printf("%c",*tmp);
     tmp++;
 }  
 printf("\n"); 
 str = strstr(packet,"qq.com");
 if(str){
     printf("This is web qq protocol\n");
     webqq_num++;
     flag = webqq;
     webqq_bytes += pcap_header->len;
 }
}

void msnms_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,char *packet){
    msnms_num++;
    msnms_bytes += pcap_header->len;
    char *tmp = packet;
    char *str;
    str = strstr(packet,"\r\n\r\n");
    if(str){
	while(tmp != str){
	    printf("%c",*tmp);
	    tmp++;
	}
	printf("\n");
    }
    else{
	while(*tmp != '\0'){
	    printf("%c",*tmp);
	    tmp++;
	}
    }
}
