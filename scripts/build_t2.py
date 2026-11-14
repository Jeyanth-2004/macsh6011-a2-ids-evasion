#!/usr/bin/env python3
from scapy.all import *
c="192.168.56.10"; s="192.168.56.20"; sp=40002; dp=80
ben=b"GET /XXXXXXXXX_shell.php HTTP/1.1\r\nHost: 192.168.56.20\r\n\r\n"
pkts=[
 IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="S",seq=1000),
 IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="SA",seq=5000,ack=1001),
 IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="A",seq=1001,ack=5001),
 IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="PA",seq=1001,ack=5001)/Raw(ben),
 IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="PA",seq=1006,ack=5001)/Raw(b"malicious"),
 IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="A",seq=5001,ack=1001+len(ben)),
]
wrpcap("/tmp/t2.pcap",pkts); print("wrote t2 partial-overlap")
