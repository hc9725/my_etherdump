#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/in.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
void strcut(char *s, char *sub,int m, int n) //用参数sub来保存结果，所以函数不用返回值了
{
	int i;
	for (i=0;i<n;i++)
		sub[i]=s[m+i-1];
		sub[i]='\0';
}
int main(int argc, char **argv)
{
	int sock, n, tcp_udp;
	char buffer[2048];
	unsigned char *iphead, *ethhead, *tcphead, *udphead;
	unsigned char tmp[20];	
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0)
	{
		perror("socket");
		exit(1);
	}
	while(1)
	{
		printf("----------cautured----------\n");
		n = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
		printf("%d bytes read\n", n);
		if(n < 42)
		{
			perror("recvfrom():");
			printf("Incomplete packet(errno is %d)\n",errno);
			close(sock);
			exit(0);
		}

		ethhead = buffer;
		printf("Source MAC address:"
			"%02x:%02x:%02x:%02x:%02x:%02x\n",
			ethhead[0],ethhead[1],ethhead[2],
			ethhead[3],ethhead[4],ethhead[5]);
		printf("Destination MAC address:"
			"%02x:%02x:%02x:%02x:%02x:%02x\n",
			ethhead[6],ethhead[7],ethhead[8],
			ethhead[9],ethhead[10],ethhead[11]);
		if(ethhead[12] == 0x08 && ethhead[13] == 0x00)
		{	
			printf("------IP protocol-------\n");
			iphead = buffer + 14;
			if(*iphead == 0x45)
			{
				printf("Version: 4\nHeadr length:20bytes\n");
				printf("Total Length:%d\n",(iphead[2]<<8) + iphead[3]);
				printf("Identification:0x%02x%02x\n",iphead[4],iphead[5]);
				printf("Flags:0x%02x\n",iphead[6]);
				printf("Frgment offset: %d\n",iphead[7]);
				printf("Time to live: %d\n",iphead[8]);
				if(iphead[9] == 0x11)
				{
					printf("Protocol: UDP\n");	
					tcp_udp = 2;
					udphead = iphead +20;
				}	
				else if(iphead[9] == 0x06)
				{
					printf("Protocol: TCP\n");
					tcp_udp = 1;
					tcphead = iphead+20;
				}	
				printf("header checksum: 0x%02x%02x\n", iphead[10],iphead[11]);
				printf("Source host %d.%d.%d.%d\n",
					iphead[12],iphead[13],
					iphead[14],iphead[15]);
				printf("dest host %d.%d.%d.%d\n",
					iphead[16],iphead[17],
					iphead[18],iphead[19]);
				printf("source, dest ports %d,%d\n",
					(iphead[20]<<8) + iphead[21],
					(iphead[22]<<8) + iphead[23]);
				printf("%02x\n",iphead[20]);
				//if( *iphead == 0x45)
				//{
				if(tcp_udp == 1)
				{
					printf("-----TCP protocol----\n");
					//printf("%02x\n",tcphead[0]);
					printf("source, dest ports %d, %d\n",
						(tcphead[0]<<8) + tcphead[1],
						(tcphead[2]<<8) + tcphead[3]);
					printf("Header length: %d\n",tcphead[12]);
					printf("Flags: 0x%02x%02x\n",tcphead[12], tcphead[13]);
					printf("window size value: %d\n",(tcphead[14]<<8) + tcphead[15]);
					printf("Check sum: ox%02x%02x\n",tcphead[16],tcphead[17]);
					//strcut(tcphead,tmp,0,2);
					//printf("ports%s\n",tmp);
					/*printf("Source host %d.%d.%d.%d\n",
						iphead[12],iphead[13],
						iphead[14],iphead[15]);
					printf("dest host %d.%d.%d.%d\n",
						iphead[16],iphead[17],
						iphead[18],iphead[19]);
					printf("source, dest ports %d,%d\n",
						(iphead[20]<<8) + iphead[21],
						(iphead[22]<<8) + iphead[23]);
				//	printf("Layer-4 protocol %d\n", iphead[9]);*/
				}
				else if (tcp_udp == 2)
				{
					printf("-----UDP protocol----\n");
					printf("source, dest ports %d, %d\n",
						(udphead[0]<<8) + udphead[1],
						(udphead[2]<<8) + udphead[3]);
					printf("Length: %d\n",(udphead[4]<<8) + udphead[5]);
					printf("Checksum: 0x%02x%02x\n", udphead[6],udphead[7]);
				}
	
			}
			printf("\n\n\n");

		
		}
	}

}
