from scapy.all import *

def print_pkt(pkt):
	if 'IP' in pkt :
        	print(pkt['IP'].src)

pkt = sniff(filter='icmp and dst host 10.0.2.15', prn=print_pkt)
