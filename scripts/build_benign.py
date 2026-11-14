#!/usr/bin/env python3
from scapy.all import *
c="192.168.56.10"; s="192.168.56.20"; dp=80
urls=[b"/index.html",b"/about.php",b"/contact.html",b"/images/logo.png",b"/css/style.css",b"/js/app.js",b"/products.php",b"/blog/post1.html",b"/login.php",b"/search?q=test"]
pkts=[]; sp=41000
for u in urls:
    req=b"GET "+u+b" HTTP/1.1\r\nHost: 192.168.56.20\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
    pkts += [
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="S",seq=1000),
      IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="SA",seq=5000,ack=1001),
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="A",seq=1001,ack=5001),
      IP(src=c,dst=s)/TCP(sport=sp,dport=dp,flags="PA",seq=1001,ack=5001)/Raw(req),
      IP(src=s,dst=c)/TCP(sport=dp,dport=sp,flags="A",seq=5001,ack=1001+len(req)),
    ]; sp+=1
wrpcap("/tmp/benign.pcap",pkts)
print("wrote benign.pcap:",len(pkts),"packets,",len(urls),"requests")
