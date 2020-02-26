#include<stdio.h>
#include<pcap.h>
#include"getdevice.h"

int main(int argc, char *argv[])
{
	const char *dev = getDevice(argv[1]);
	if(!dev) return 1;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	handle = pcap_open_live(dev, BUFSIZ, 0, 1000, errbuf);
	if(!handle)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
	return 0;
}
