#!/usr/bin/env python3
from scapy.all import *
c = "192.168.56.10"; s = "192.168.56.20"; sp = 40000; dp = 80
mal = b"GET /malicious_shell.php HTTP/1.1\r\nHost: 192.168.56.20\r\n\r\n"
pkts = [
    IP(src=c, dst=s)/TCP(sport=sp, dport=dp, flags="S",  seq=1000),
    IP(src=s, dst=c)/TCP(sport=dp, dport=sp, flags="SA", seq=5000, ack=1001),
    IP(src=c, dst=s)/TCP(sport=sp, dport=dp, flags="A",  seq=1001, ack=5001),
    IP(src=c, dst=s)/TCP(sport=sp, dport=dp, flags="PA", seq=1001, ack=5001)/Raw(mal),
    IP(src=s, dst=c)/TCP(sport=dp, dport=sp, flags="A",  seq=5001, ack=1001+len(mal)),
]
wrpcap("/tmp/baseline.pcap", pkts)
print("wrote /tmp/baseline.pcap with", len(pkts), "packets")
