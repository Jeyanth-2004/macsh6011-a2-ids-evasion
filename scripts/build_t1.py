#!/usr/bin/env python3
from scapy.all import *
c = "192.168.56.10"; s = "192.168.56.20"; sp = 40000; dp = 80
mal = b"GET /malicious_shell.php HTTP/1.1\r\nHost: 192.168.56.20\r\n\r\n"
psh = IP(src=c, dst=s, id=0xABCD)/TCP(sport=sp, dport=dp, flags="PA", seq=1001, ack=5001)/Raw(mal)
mseg = bytes(psh)[20:]                 # malicious TCP segment
bseg = bytearray(mseg); bseg[24:32] = b"XXXXXXXX"; bseg = bytes(bseg)  # benign in token region
f1 = IP(src=c, dst=s, id=0xABCD, flags="MF", frag=0, proto=6)/Raw(bseg[0:48])   # FIRST = benign
f2 = IP(src=c, dst=s, id=0xABCD, flags="MF", frag=3, proto=6)/Raw(mseg[24:32])  # LATER overlap = malicious
f3 = IP(src=c, dst=s, id=0xABCD, flags=0,   frag=6, proto=6)/Raw(mseg[48:])     # tail
pkts = [
    IP(src=c, dst=s)/TCP(sport=sp, dport=dp, flags="S",  seq=1000),
    IP(src=s, dst=c)/TCP(sport=dp, dport=sp, flags="SA", seq=5000, ack=1001),
    IP(src=c, dst=s)/TCP(sport=sp, dport=dp, flags="A",  seq=1001, ack=5001),
    f1, f2, f3,
    IP(src=s, dst=c)/TCP(sport=dp, dport=sp, flags="A",  seq=5001, ack=1001+len(mal)),
]
wrpcap("/tmp/t1.pcap", pkts)
print("wrote /tmp/t1.pcap")
