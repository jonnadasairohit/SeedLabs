#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(iface=['br-c3a8b70fdb97','ens33'], filter='icmp',prn=print_pkt)
