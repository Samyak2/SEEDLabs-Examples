#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>

const char* getDevice(char *device)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	char *ret_device;
	pcap_if_t *alldevs;
	pcap_if_t *iterdev;
	pcap_addr_t *iteraddr;
	int ret = 0;
	ret = pcap_findalldevs(&alldevs, errbuf);
	if(ret == -1)
	{
		fprintf(stderr, "Could not find default device: %s\n", errbuf);
		return NULL;
	}
	iterdev = alldevs;
	while(iterdev)
	{
		if(strcmp(iterdev->name, device))
		{
			return device;
		}
		iterdev = iterdev->next;
	}
	pcap_freealldevs(alldevs);
	return NULL;
}


