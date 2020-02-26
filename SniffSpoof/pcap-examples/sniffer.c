#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

	/* Ethernet header */
	struct sniff_ethernet {
		u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
		u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
		u_short ether_type; /* IP? ARP? RARP? etc */
	};

	/* IP header */
	struct sniff_ip {
		u_char ip_vhl;		/* version << 4 | header length >> 2 */
		u_char ip_tos;		/* type of service */
		u_short ip_len;		/* total length */
		u_short ip_id;		/* identification */
		u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		u_char ip_ttl;		/* time to live */
		u_char ip_p;		/* protocol */
		u_short ip_sum;		/* checksum */
		struct in_addr ip_src,ip_dst; /* source and dest address */
	};
	#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
	#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	/* TCP header */
	typedef u_int tcp_seq;

	struct sniff_tcp {
		u_short th_sport;	/* source port */
		u_short th_dport;	/* destination port */
		tcp_seq th_seq;		/* sequence number */
		tcp_seq th_ack;		/* acknowledgement number */
		u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		u_short th_win;		/* window */
		u_short th_sum;		/* checksum */
		u_short th_urp;		/* urgent pointer */
};

#define SIZE_ETHERNET 14

/* This function will be invoked by pcap for each captured packet.
 * We can process each packet inside the function.
 *  */
void got_packet(u_char *args, const struct pcap_pkthdr *header,
		        const u_char *packet)
{
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;
	u_int size_ip;
	u_int size_tcp;
	char temp_addr_buf[INET_ADDRSTRLEN+1];
	const char *dst;

	ethernet = (struct sniff_ethernet*) packet;
	
	printf("---ETHERNET---\n");
	dst = inet_ntop(AF_INET, &(ethernet->ether_shost), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tSource: %s\n", dst);
	dst = inet_ntop(AF_INET, &(ethernet->ether_dhost), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tDestination: %s\n", dst);
	printf("\tType: %d\n", ethernet->ether_type);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);

//	char temp_addr_buf[INET_ADDRSTRLEN+1];
//	const char *dst;

	size_ip = IP_HL(ip) * 4;
	if(size_ip < 20)
	{
		fprintf(stderr, "Invalid size of IP packet: %d bytes\n", size_ip);
		//return;
	}
	printf("---IP---\n");
	dst = inet_ntop(AF_INET, &(ip->ip_src), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tSource IP: %s\n", dst);
	dst = inet_ntop(AF_INET, &(ip->ip_dst), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tDestination: %s\n", dst);
	printf("\tTime to Live: %d\n", ip->ip_ttl);
	printf("\tLength: %d\n", ip->ip_len);
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	if(size_tcp < 20)
	{
		fprintf(stderr, "Invalid size of TCP packet: %d bytes\n", size_tcp);
		//return;
	}
	printf("---TCP---\n");
	//dst = inet_ntop(AF_INET, &(tcp->th_sport), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tSource Port: %d\n", ntohs(tcp->th_sport));
	//dst = inet_ntop(AF_INET, &(tcp->th_dport), temp_addr_buf, INET_ADDRSTRLEN+1);
	printf("\tDestination Port: %d\n", ntohs(tcp->th_dport));

	payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	printf("Payload: %s\n", payload);
	printf("*******************************\n");
}
int main()
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "tcp";
	bpf_u_int32 net;
	    // Step 1: Open live pcap session on NIC with name eth3
	    // //         Students needs to change "eth3" to the name
	    // //         found on their own machines (using ifconfig).
	handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
	    // // Step 2: Compile filter_exp into BPF psuedo-code
	pcap_compile(handle, &fp, filter_exp, 0, net);
	pcap_setfilter(handle, &fp);
	    // // Step 3: Capture packets
	pcap_loop(handle, -1, got_packet, NULL);
	
	pcap_freecode(&fp);
	pcap_close(handle);   //Close the handle
	return 0;
}
	    // // Note: don’t forget to add "-lpcap" to the compilation command.
	    // // For example: gcc -o sniff sniff.c -lpcap
