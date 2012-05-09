/*
 * OpenDPI_demo.c
 * Copyright (C) 2009-2011 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */



#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>

#ifdef __linux__
#include <linux/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#else
# include "linux_compat.h"
#endif

#include <pcap.h>

#include"appid.h"
// cli options
static char *_pcap_file = NULL;

// pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;


static appid_t *appid_demo = NULL;

static void parseOptions(int argc, char **argv)
{
	int opt;


	while ((opt = getopt(argc, argv, "f:e:")) != EOF) {
		switch (opt) {
		case 'f':
			_pcap_file = optarg;
			break;
		case 'e':
			printf("ERROR: option -e : DEBUG MESSAGES DEACTIVATED\n");
			exit(-1);
			break;
		}
	}

	// check parameters
	if (_pcap_file == NULL || strcmp(_pcap_file, "") == 0) {
		printf("ERROR: no pcap file path provided; use option -f with the path to a valid pcap file\n");
		exit(-1);
	}
}



static void openPcapFile(void)
{
	_pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);

	if (_pcap_handle == NULL) {
		printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
		exit(-1);
	}
	_pcap_datalink_type = pcap_datalink(_pcap_handle);
}

static void closePcapFile(void)
{
	if (_pcap_handle != NULL) {
		pcap_close(_pcap_handle);
	}
}

// executed for each packet in the pcap file
//#define IPPROTO_TCP	6
//#define IPPROTO_UDP	17
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{

    const struct ethhdr *ethernet = (struct ethhdr *) packet;
    struct iphdr *iph = (struct iphdr *) &packet[sizeof(struct ethhdr)];

    appid_hexdump(0, (void*)packet, header->len);
    printf("iph->tot_len :%u\n",ntohs(iph->tot_len));
    printf("iph->tot_len :%u\n",(iph->tot_len));    
    if (IPPROTO_TCP == iph->protocol){
        struct tcphdr *tcp_hdr =  (struct tcphdr *)(&packet[sizeof(struct ethhdr) + sizeof(struct iphdr)]);   
        appid_process(appid_demo, iph->protocol, ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest),
            (void*)((char*)tcp_hdr+ sizeof(struct tcphdr)),  (ntohs(iph->tot_len) -16 - 20));
    }else if(IPPROTO_UDP == iph->protocol){
        struct udphdr *udp_hdr =  (struct udphdr *)(&packet[sizeof(struct ethhdr) + sizeof(struct iphdr)]);   
        appid_process(appid_demo, iph->protocol, ntohs(udp_hdr->source), ntohs(udp_hdr->dest),
            (void*)((char*)udp_hdr+ sizeof(struct udphdr)),  (ntohs(iph->tot_len) -16 -8));    
    }else{
        printf("ERROR :drop packet\n");
    }
}

static void runPcapLoop(void)
{
	if (_pcap_handle != NULL) {
		pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
	}
}

extern int appid_debug ;
int main(int argc, char **argv)
{
#if 0
 int i =0;
 for(i = 0;i <16;i++)
    printf("iph->tot_len :%c\n",('0' + i));   
 return 0;
 #endif
 
        appid_debug = 1;
	parseOptions(argc, argv);

        appid_demo = appid_open();
	openPcapFile();
	runPcapLoop();
	closePcapFile();
        appid_close(&appid_demo);

	return 0;
}
