#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct _tmp_data
{
	char protocol[10];
	char srcip[20];
	char desip[20];
	int srcport;
	int desport;
	char tcp_udp[5];
}*tmp_data;
tmp_data getData;
int ip = 0;
int tcp = 1;
int udp = 2;
int arp = 3;
int oicq = 4;
int http = 5;
int webqq = 6;
int msnms = 7;

int flag = 0;
int other_num = 0;
int oicq_num = 0;
int tcp_num = 0;
int udp_num = 0;
int ip_num = 0;
int arp_num = 0;
int http_num = 0;
int webqq_num = 0;
int msnms_num = 0;
long other_bytes = 0;
long oicq_bytes = 0;
long tcp_bytes = 0;
long udp_bytes = 0;
long ip_bytes = 0;
long arp_bytes = 0;
long http_bytes = 0;
long webqq_bytes = 0;
long msnms_bytes = 0;
void timer_handler(int signo)
{
	char str;
	if(signo == SIGALRM)
	{
		printf("this is the time of update\n");
		exit(0);
	}
	else
	{
		printf("unexpected signal\n");	
	}
}

int main()
{
	pcap_t *pt;
	char *dev;
	char errbuf[128];
	bpf_u_int32 maskp, netp;
	int ret,i=0,inum;
	int pcap_time_out = 5;
	char filter[128];
	unsigned char *packet;
	struct pcap_pkthdr hdr;
	pcap_if_t *alldevs = NULL, *d;
	pid_t pid;
	char ch[10],str;
	attHead att_head;
	static long long intnum = 0;
	char timt[20];
	extern int ip_num;
/*	att_head = init_attHead();
	printf("%p\n",att_head);
	if(pcap_findalldevs(&alldevs,errbuf)== -1)
	{
		fprintf(stderr,"find interface failed!");
		return;
	}
	for(d = alldevs; d; d=d->next)
	{
		printf("%d. %s\n",++i, d->name);
		if(d->description)
		{
			printf("(%s)\n",d->description);
		}
		else
			printf("(no description available)\n");
	}
	if(i == 1)
	{
		dev = alldevs->name;	
	}
	else
	{
		printf("input a interface:1-%d)",i);
		scanf("%d", &inum);
		if(inum <1 || inum >i)
		{
			printf("interface number out of range\n");
			return;
		}
		for(d = alldevs, i=1; i<inum; d = d->next, i++);
		dev = d->name;
	}
	printf("dev:%s\n",dev);*/
	dev = "eth0"
	ret = pacp_lookupnet(dev, &netp, &maskp,errbuf);
	printf("");
	if(ret == -1)
	{
		fprintf(stderr, "%s\n",errbuf);
		return;
	}
	pt = pcap_openlive(dev, BUFSIZ, 1, pcap_time_out, errbuf);
	if(pt == NULL)
	{
		fprintf(stderr, "openn error :%s\n", errbuf);
		return;
	}
	while(1)
	{
		//printf("if you want to quit press y , else  pressany other key!\n");
		//scanf("%c", &str);
		//if(str == 'y')
		//	break;
		pid = vfork();
		if(pid < 0)
		{
			printf("fail to fork\n");
		}
		else if(pid == 0)
		{
		//	if(signal(SIGALRM,timer_handler) == SIG_ERR)
		//	{
		//		perror("can't set handler for SIGALRM\n");
		//		exit(0);
		//	}
		//	alarm(1800);
			while(1)
			{
				packet = (char *)pacp_next(pt, &hdr);
				if(packet == NULL) continue;
				else
				{
					printf("\n\n\n");
					printf("get a packet\n");
					getData = (tmp_data)malloc(sizeof(struct _tmp_data));
					ethernet_packet_callback(NULL, &hdr,packet);
					num++;
					printf("\n");
					if(flag == arp)
					{
						strcpy(time, getTime("%k:%M:%S"));
						insert_data(att_head, num, time, "arp","xxxxxxxx","broadcast",0,0,"arp");
						printMemort(att_head);
						flag = 0;
					}
					else
					{
						switch(flag)
						{
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
							strcpy(getData->srcip,"xxxxxxxx");
							strcpy(getData->desip,"xxxxxxxx");
							getData->srcport = 0;
							getData->desport = 0;
							strcpy(getData->tcp_udp,"xxx");
							other_num++;
							other_bytes = other_bytes + hdr.len;
							break;
						}
						strcpy(time,getTime("%k:%M:%S"));
						insert_data(att_head, num,time,ch,getData->srcip,getData->desip, getData->srcport,getData->desport, getData->tcp_udp);
						printMemort(att_head);
						flag = 0;
					}
				}
				printf("\n");
				printf("其它包的总数:%d   其它凶的总字节数：%ld\n",other_num,other_bytes);
				printf("ip包的总数：%d   ip包的总数：%ld\n",ip_num,ip_bytes);
				printf("tcp包的总数：%d   tcp包的总数：%ld\n",tcp_num,tcp_bytes);
				printf("arp包的总数：%d   arp包的总数：%ld\n",arp_num,arp_bytes);
				printf("idp包的总数：%d   udp包的总数：%ld\n",udp_num,udp_bytes);
				printf("oicq包的总数：%d   oicq包的总数：%ld\n",oicq_num,oicq_bytes);
				printf("webqq包的总数：%d   webqq包的总数：%ld\n",webqq_num,webqq_bytes);
				printf("http包的总数：%d   http包的总数：%ld\n",http_num,http_bytes);
				printf("msnms包的总数：%d   msnms包的总数：%ld\n",msnms_num,msnms_bytes);
				
			}
		}else
		{
			if(wait(NULL) == -1)
			{
				printf("fail to wait\n");
				exit(1);
			}
		}
	}
	pcap_close(pt);
	saveTable(att_head);
	free_data(att_head);
	cat("/home/guest/pcap/pcap/data/test");
	return 0;
}
