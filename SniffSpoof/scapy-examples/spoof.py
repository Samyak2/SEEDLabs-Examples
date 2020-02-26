from scapy.all import *

a = IP()
a.src = '172.217.166.100'
a.dst = '10.0.2.4'
b = ICMP()
p = a/b
send(p)
