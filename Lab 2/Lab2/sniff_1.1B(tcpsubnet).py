#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(iface=[ 'ens33'], filter='net 153.91.1.0/24',prn=print_pkt)
