#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<netinet/in.h>
#include<sys/socket.h>
#include<arpa/inet.h>

void printsockaddrp(struct sockaddr* sockaddrp, char* msg)
{
	if(sockaddrp)
	{
		char temp_addr_buf[INET6_ADDRSTRLEN+1];
		const char *dst;
		if (sockaddrp->sa_family == AF_INET)
		{
			dst = inet_ntop(AF_INET, &(((struct sockaddr_in *)sockaddrp)->sin_addr), temp_addr_buf, INET_ADDRSTRLEN+1);
		}
		else if(sockaddrp->sa_family == AF_INET6)
		{
			dst = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sockaddrp)->sin6_addr), temp_addr_buf, INET6_ADDRSTRLEN+1);
		}
		if(dst)
		printf("%s: %s\n", msg, dst);
		/*if (sockaddrp->sa_family == AF_INET) 
		{
			struct sockaddr_in *inaddr_ptr = (struct sockaddr_in *)sockaddrp;
			printf("%s: %s\n", msg, inet_ntoa(inaddr_ptr->sin_addr));
		}
		else if(sockaddrp->sa_family == AF_INET6)
		{
			struct sockaddr_in6 *inaddr_ptr = (struct sockaddr_in6 *)sockarrp;
			printf("%s: %s\n", msg, inet
		}*/
	}
}

int main(int argc, char *argv[])
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *iterdev;
	pcap_addr_t *iteraddr;
	int ret = 0;

	ret = pcap_findalldevs(&alldevs, errbuf);
	if(ret == -1)
	{
		fprintf(stderr, "Could not find default device: %s\n", errbuf);
		return -1;
	}
	printf("Found devices\n");
	iterdev = alldevs;
	while(iterdev)
	{
		printf("Device name: %s\n", iterdev->name);
		printf("\tDescription: %s\n", iterdev->description);
		iteraddr = iterdev->addresses;
		while(iteraddr)
		{
			printsockaddrp(iteraddr->addr, "\tAddress");
			printsockaddrp(iteraddr->addr, "\t  Netmask");
			printsockaddrp(iteraddr->broadaddr, "\t  Broadcast address");
			printsockaddrp(iteraddr->dstaddr, "\t  Destination address");
			//if(iteraddr->netmask)
			//	printf("\tNetmask: %s\n", iteraddr->netmask->sa_data);
			iteraddr = iteraddr->next;
		}
		printf("\tFlags: %d\n", iterdev->flags);
		iterdev=iterdev->next;
	}
	pcap_freealldevs(alldevs);
	return 0;
}
