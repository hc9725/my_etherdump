#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <math.h>
//#pragma pack (1)
struct oicq_hdr{
    uint8_t flag;
    uint16_t version;
    uint16_t command;
    uint16_t seq;
    uint32_t data;
}__attribute__((__packed__));
//typedef struct oicq_hdr _oicq_hdr;
static int oicq_num = 0;
static int tcp_num = 0;
static int udp_num = 0;
static int ip_num = 0;
static int arp_num = 0;

static long oicq_bytes = 0;
static long tcp_bytes = 0;
static long udp_bytes = 0;
static long ip_bytes = 0;
static long arp_bytes = 0;

void command_packet_callback(uint16_t command){
    int i = 42;
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
	    printf("command: receive message (%d)\n",ntohs(command)); break;
	case 0x001d:
	    printf("command: request key (%d)\n",ntohs(command)); break;
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

void oicq_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content){
    
    oicq_num++;
    oicq_bytes += pcap_header->len;
    struct oicq_hdr *oicqhdr = (struct oicq_hdr *)(packet_content+14+20+8);
    printf("-----oicq protocol-----\n");
    printf("flag:oicq packet(0x%02x)\n",oicqhdr->flag);
    printf("version: 0x%02x\n",ntohs(oicqhdr->version));
    command_packet_callback(oicqhdr->command);
    printf("sequence: %d\n",ntohs(oicqhdr->seq));
    printf("data (oicq number,if sender is client):%u\n",ntohl(oicqhdr->data));
}

void tcp_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
 struct tcphdr *tcpptr=(struct tcphdr *)(packet_content+14+20);
 int i = 0;
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
 if(packet_content[i] != '\0'){
     printf("flag:0x%02x\n",packet_content[i]);
     switch(packet_content[i]){
	 case 0x02:
	     printf("This is a oicq protocol\n");
	     oicq_packet_callback(argument,pcap_header,packet_content);
	     break;
	 default:
	     break;
     }
 }
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

 switch(ipptr->protocol) {
  case 6:
   printf("This is tcp protocol\n");
   tcp_packet_callback(argument,pcap_header,packet_content);
   break;
  case 1:
   printf("This is icmp protocol\n");
   break;
  case 17:
   printf("This is udp protocol\n");
   udp_packet_callback(argument,pcap_header,packet_content);
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

void ethernet_packet_callback(unsigned char *argument,const struct pcap_pkthdr* pcap_header,const unsigned char *packet_content) {
 struct ethhdr *ethptr;
 struct iphdr *ipptr;
 unsigned char *mac;
 int i;
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
   ip_packet_callback(argument,pcap_header,packet_content);
   break;
  case 0x0806:
   printf("this is a ARP protocol\n");
   arp_packet_callback(argument,pcap_header,packet_content);
   break;
  case 0x8035:
   printf("this is a RARP protocol\n");
   break;
  default:
   break; 
 }

}

int main()
{
 pcap_t *pt;
 char *dev;
 char errbuf[128];
 struct bpf_program fp;
 bpf_u_int32 maskp,netp;
 int ret,i=0,inum;
 int pcap_time_out=5;
 char filter[128];
 unsigned char *packet;
 struct pcap_pkthdr hdr;
 pcap_if_t *alldevs = NULL,*d;

/* if(pcap_findalldevs(&alldevs,errbuf)==-1) {
  fprintf(stderr,"find interface failed!\n");
  return;
 }
 for(d=alldevs;d;d=d->next){
  printf("%d. %s\n",++i,d->name);
  if(d->description)
   printf("(%s)\n",d->description);
  else
   printf("(no description available)\n");
 }
 
 if(i==1)
  dev=alldevs->name;
 else {
  printf("input a interface:(1-%d)",i);
  scanf("%d",&inum);
  if(inum<1||inum>i) {
   printf("interface number out of range\n");
   return;
  }
 
  for(d=alldevs,i=1;i<inum;d=d->next,i++);
  dev=d->name;
 }
 
 //
 dev=pcap_lookupdev(errbuf);
 if(dev==NULL){
  fprintf(stderr,"%s\n",errbuf);
  return;
 }
 ///
 printf("dev:%s\n",dev);
 */
 dev = "eth0";
 ret=pcap_lookupnet(dev,&netp,&maskp,errbuf);
 printf("");
 if(ret==-1){
  fprintf(stderr,"%s\n",errbuf);
  return;
 }
 pt=pcap_open_live(dev,BUFSIZ,1,pcap_time_out,errbuf);
 if(pt==NULL){
  fprintf(stderr,"open error :%s\n",errbuf);
  return;
 }
/* sprintf(filter,"");
 if(pcap_compile(pt,&fp,filter,0,netp)==-1) {
  fprintf(stderr,"compile error\n");
  return;
 }
 if(pcap_setfilter(pt,&fp)==-1) {
  fprintf(stderr,"setfilter error\n");
  return;
 }
 pcap_loop(pt,-1,tcp_packet_callback,NULL);
 */
 while(1)
 {
	//  printf("wait packet:filter %s\n",filter);
 	 packet=(char *)pcap_next(pt,&hdr);
 	 if(packet==NULL)
 	  continue;
 	 else
	 {
	 	 printf("\n\n\n");
   		 printf("get a packet\n");
   		 printf("The grab length of packet is %d\n",hdr.caplen);
  		 printf("The length of packet is %d\n",hdr.len);
  		 ethernet_packet_callback(NULL,&hdr,packet); 
  		 printf("\n");
  		 printf("The packet content is:\n");
  		 for(i = 0; i < hdr.len; i++) 
		 {
      			printf("%02x ",packet[i]);
   		 }
  	}
  	printf("\n");
  	printf("ip包的总数：%d   ip包的总字节数：%ld\n",ip_num,ip_bytes);
  	printf("arp包的总数：%d   arp包的总字节数：%ld\n",arp_num,arp_bytes);
  	printf("tcp包的总数：%d   tcp包的总字节数：%ld\n",tcp_num,tcp_bytes);
  	printf("udp包的总数：%d   udp包的总字节数：%ld\n",udp_num,udp_bytes);
  	printf("oicq包的总数：%d   oicq包的总字节数：%ld\n",oicq_num,oicq_bytes);
}
 pcap_close(pt);
 return 0;
}

