#!/usr/bin/env python3
from scapy.all import *
c="192.168.56.10"; s="192.168.56.20"; sp=40003; dp=80
mal=b"GET /malicious_shell.php HTTP/1.1\r\nHost: 192.168.56.20\r\n\r\n"
psh=IP(src=c,dst=s,id=0xCAFE)/TCP(sport=sp,dport=dp,flags="PA",seq=1001,ack=5001)/Raw(mal)
seg=bytes(psh)[20:]
t0=1000000000.0
hs1=IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="S",seq=1000); hs1.time=t0
hs2=IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="SA",seq=5000,ack=1001); hs2.time=t0
hs3=IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="A",seq=1001,ack=5001); hs3.time=t0
f1=IP(src=c,dst=s,id=0xCAFE,flags="MF",frag=0,proto=6)/Raw(seg[0:24]); f1.time=t0+1
f2=IP(src=c,dst=s,id=0xCAFE,flags="MF",frag=3,proto=6)/Raw(seg[24:48]); f2.time=t0+75
f3=IP(src=c,dst=s,id=0xCAFE,flags=0,frag=6,proto=6)/Raw(seg[48:]); f3.time=t0+150
wrpcap("/tmp/t4.pcap",[hs1,hs2,hs3,f1,f2,f3])
print("wrote t4 (fragments 75s apart, exceeds 60s defrag timeout)")
