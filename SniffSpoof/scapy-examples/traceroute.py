from scapy.all import *

req = IP()
req.dst = 'www.google.com'
req.ttl = 1
b = ICMP()

#def print_pkt(pkt):
#        if 'IP' in pkt:
#                print(pkt['IP'].src)

# pkt = sniff(filter='dst host 10.0.2.15', prn=print_pkt)

for i in range(1,11):
	req.ttl = i
	send(req/b)
	#sniff(filter='dst host 10.0.2.15', prn=print_pkt, count=1)

