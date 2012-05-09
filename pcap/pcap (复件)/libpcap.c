#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "ip_list.c"
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#include "resolve.c"
#include "table.c"
#include "save_table.c"
void timer_handler(int signo){
    char str;
    if(signo == SIGALRM){
 //       printf("this is the time of update\n");
        exit(0);
    }
    else{
        printf("unexpected signal\n");
    }
}

int main(){
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
    pid_t pid;
    char ch[10],str = 'n';
    attHead att_head;

    head = init_ip_list(head);
    att_head = init_attHead();
    if(pcap_findalldevs(&alldevs,errbuf)==-1) {
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

    printf("dev:%s\n",dev);
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

while(1) {
    printf("if you want to quit press y,else press any other key!\n");
    scanf("%c",&str);
    if(str == 'y')break;
  pid = vfork();
  if(pid < 0){
      printf("fail to fork\n");
  }else if(pid == 0){
      if(signal(SIGALRM,timer_handler) == SIG_ERR){
	  perror("can't set handler for SIGALRM\n");
	  exit(0);
      }
      alarm(1);
      while(1){
      packet=(char *)pcap_next(pt,&hdr);
      if(packet==NULL) continue;
      else{
         printf("\n\n\n");
   	 printf("get a packet\n");
   	 ethernet_packet_callback(NULL,&hdr,packet); 
	 num++;
   	 printf("\n");
	 if(flag == arp){
	     init_data(att_head,num,"arp","xxxxxxxx","broadcast");
	     printMemory(att_head);
	     flag = 0;
	 }
	 else{
	     switch(flag){
		 case ip:
		     strcpy(ch,"ip");break;
		 case tcp:
		     strcpy(ch,"tcp");break;
		 case udp:
		     strcpy(ch,"udp");break;
		 case http:
		     strcpy(ch,"http");break;
		 case oicq:
		     strcpy(ch,"oicq");break;
		 case webqq:
		     strcpy(ch,"webqq");break;
		 case msnms:
		     strcpy(ch,"msnms");break;
		 default:
		     strcpy(ch,"xxx");
		     strcpy(srcip,"xxxxxxxx");
		     strcpy(desip,"xxxxxxxx");
		     other_num++;
		     other_bytes = other_bytes+hdr.len;
		     break;
	     }
		 init_data(att_head,num,ch,srcip,desip);
		 printMemory(att_head);
	         flag = 0;
	 }
     }
  	printf("\n");
	printf("其他包的总数：%d   其他包的总字节数：%ld\n",other_num,other_bytes);
  	printf("ip包的总数：%d   ip包的总字节数：%ld\n",ip_num,ip_bytes);
  	printf("arp包的总数：%d   arp包的总字节数：%ld\n",arp_num,arp_bytes);
  	printf("tcp包的总数：%d   tcp包的总字节数：%ld\n",tcp_num,tcp_bytes);
  	printf("udp包的总数：%d   udp包的总字节数：%ld\n",udp_num,udp_bytes);
  	printf("oicq包的总数：%d   oicq包的总字节数：%ld\n",oicq_num,oicq_bytes);
	printf("http包的总数：%d   http包的总字节数: %ld\n",http_num,http_bytes);
	printf("web qq包的总数：%d   web qq包的总字节数: %ld\n",webqq_num,webqq_bytes);
	printf("msnms包的总数：%d   msnms包的总字节数: %ld\n",msnms_num,msnms_bytes);
	display_ip_list(head);
      }
  } else{
      delete_ip_list(head,1);
      if(wait(NULL) == -1){
      	printf("fail to wait\n");
      	exit(1);
      }
   }
 }
 pcap_close(pt);
 saveTable(att_head);
 free_ip_list(head);
 free_data(att_head);
 return 0;
/*
 pt = pcap_open_offline("msn.pcap",errbuf);
 if(pt == NULL){
     printf("ERROR:could not open pcap file: %s\n",errbuf);
     exit(-1);
 }
 pcap_loop(pt,-1,&ethernet_packet_callback,NULL);
 pcap_close(pt);
 return 0;*/
}








