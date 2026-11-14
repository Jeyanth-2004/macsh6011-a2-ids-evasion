#!/usr/bin/env python3
from scapy.all import *
import random
c="192.168.56.10"; s="192.168.56.20"; dp=80
paths=["/index.html","/about.php","/contact","/images/logo.png","/css/style.css",
"/js/app.js","/products.php?id=42","/blog/my-shell-guide.html","/search?q=malicious+software+review",
"/login","/api/v1/users","/download/report.pdf","/cart/checkout","/static/fonts/x.woff2",
"/wp-content/themes/x.css","/favicon.ico","/robots.txt","/sitemap.xml","/news/2026/article",
"/help/faq.html"]
pkts=[]; sp=42000
for i,p in enumerate(paths):
    req=("GET "+p+" HTTP/1.1\r\nHost: 192.168.56.20\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n").encode()
    syn=1000; ackv=5000
    pkts += [
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="S",seq=syn),
      IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="SA",seq=ackv,ack=syn+1),
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="A",seq=syn+1,ack=ackv+1),
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="PA",seq=syn+1,ack=ackv+1)/Raw(req),
    ]
    # legit retransmission of SAME data (identical overlap - must NOT trigger overlap-different-data)
    if i % 3 == 0:
        pkts.append(IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="PA",seq=syn+1,ack=ackv+1)/Raw(req))
    pkts.append(IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="A",seq=ackv+1,ack=syn+1+len(req)))
    sp+=1
wrpcap("/tmp/benign2.pcap",pkts)
print("wrote benign2.pcap:",len(pkts),"packets,",len(paths),"requests, with identical retransmissions")
