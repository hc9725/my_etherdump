#include <stdio.h>
#include <pcap.h>

int main(int argc,char* argv[])
{
	void printer()
	{
		printf("A packet is capured!\n");
		return;
	}
	char ebuf[PCAP_ERRBUF_SIZE];
	pcap_t *pd = pcap_open_live("eth0",68,0,1000,ebuf);
	pcap_loop(pd,5,printer,NULL);
	pcap_close(pd);
	return 0;
}
