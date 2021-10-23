#!/usr/bin/python3

from scapy.all import *

def print_pkt(pkt):
   pkt.show()

pkt = sniff(iface=[ 'ens33'], filter='src host 192.168.253.129 and tcp and src port 23',prn=print_pkt)
