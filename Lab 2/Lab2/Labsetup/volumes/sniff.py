#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(iface=['br-c3a8b70fdb97'], filter='tcp and dst prt 23 and src host 10.9.0.5',prn=print_pkt)
