#include<stdio.h>
#include<pcap.h>
#include"getdevice.h"

int main(int argc, char *argv[])
{
	const char *dev = getDevice(argv[1]);
	if(!dev) return 1;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	char filter_exp[] = "port 23";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	}
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(!handle)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't set filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	return 0;
}
