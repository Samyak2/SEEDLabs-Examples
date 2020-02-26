from scapy.all import *
import pickle

response_ip = IP()
response_ip.src = '1.2.3.4'
icmp_resp = ICMP()
icmp_resp.type = 'echo-reply'

def printcallback(pkt):
	# with open("pkt.pkl", "wb") as f:
	#	pickle.dump(pkt, f)

	# pkt.show()
	#pkt_type = pkt['ICMP'].sprintf("{ICMP:%ICMP.type%}")
	pkt.show()
	#if pkt_type == 'echo-reply' or pkt_type == 'echo-request':
	#	pkt.show()
		#with open("pkt.pkl", "wb") as f:
                #	pickle.dump(pkt, f)
	#print("type:", pkt[ICMP].type)
	#print(dir(pkt))
	#print(pkt.layers)
	"""if ICMP in pkt and pkt_type == 'echo-request':
		# response = pkt.copy()
		# response[IP].dst = pkt[IP].src
		# del response[IP].chksum
		# del response[ICMP].chksum
		# response[IP] = response[IP].__class__(bytes(response[IP]))
		# response[ICMP] = response[ICMP].__class__(bytes(response[ICMP]))
		# response[ICMP].type = 'echo-reply'
		
		response_ip.dst = pkt[IP].src
		response_ip.src = pkt[IP].dst
		icmp_resp = ICMP()
		icmp_resp.type = 'echo-reply'
		icmp_resp.seq = pkt[ICMP].seq
		icmp_resp.id = pkt[ICMP].id
		icmp_resp = icmp_resp.__class__(bytes(icmp_resp))
		resp = response_ip/icmp_resp
		send(resp)
		#resp.show()
	"""		
sniff(filter='ip and dst host 10.0.2.4', prn=printcallback)
