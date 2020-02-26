#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(filter='src host towel.blinkenlights.nl and src port 23', prn=print_pkt)
