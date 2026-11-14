# MACSH6011 Assignment 2 — IDS Evasion: Supporting Artifacts

**Author:** Jeyanth Kannan (A00083529)
**Engine under test:** Suricata 8.0.8 RELEASE
**Method:** deterministic offline analysis (`suricata -r` over crafted pcaps)

This archive reproduces every result in the accompanying paper. A single
malicious HTTP request (`GET /malicious_shell.php`) is held constant while
four evasion techniques are applied to it; each is detected at baseline,
evades a default-configured sensor, and (for three of four) is re-detected
after a targeted countermeasure.

## Contents

```
a2_artifacts/
├── README.md              # this file
├── RESULTS.md             # the results matrix + exact commands/outputs
├── config/
│   ├── local.rules        # the two custom detection signatures
│   └── suricata.yaml      # the sensor config (host-os-policy / defrag edits noted in RESULTS)
├── pcaps/
│   ├── baseline.pcap      # clean attack — detected
│   ├── t1.pcap            # IP-fragment overlap (benign-first) — evades
│   ├── t2.pcap            # TCP segment overlap — evades
│   ├── t4.pcap            # low-and-slow + fragmentation — evades
│   ├── benign.pcap        # 10 benign requests — early FP corpus
│   └── benign2.pcap       # 20 benign requests incl. legit retransmissions — FP stress corpus
└── scripts/
    ├── build_baseline.py  # builds baseline.pcap
    ├── build_t1.py        # builds t1.pcap
    ├── build_t2.py        # builds t2.pcap
    ├── build_t4.py        # builds t4.pcap
    ├── build_benign.py    # builds benign.pcap
    └── build_benign2.py   # builds benign2.pcap (FP stress corpus)
```

## Detection signatures (`config/local.rules`)

- **sid 1000001** — matches the *normalised* request URI (`http.uri`).
- **sid 1000002** — matches the *raw* TCP payload (`content`).

Holding both lets a single result distinguish normalisation-dependent from
raw matching (central to the T3 encoding finding).

## How to reproduce any result

From a machine with Suricata 8.x installed:

```bash
# baseline — expect sid 1000001 and sid 1000002 to fire
sudo suricata -c config/suricata.yaml -S config/local.rules \
     -r pcaps/baseline.pcap -l /tmp/out -k none
sudo jq -c 'select(.event_type=="alert")|{sid:.alert.signature_id}' /tmp/out/eve.json
```

Swap `baseline.pcap` for `t1.pcap`, `t2.pcap`, or `t4.pcap` to see each
evasion (empty alert output = evaded). RESULTS.md lists the one-line
configuration change that restores detection for all four techniques
(T1 bsd-right policy, T2 check-overlap-different-data, T3 normalised
signature, T4 defrag.timeout=300).

`-k none` disables checksum validation so hand-crafted packets are inspected
on their merits — standard for offline evasion analysis.

## Testbed

VirtualBox internal network (`idslab`, isolated — no host/Internet/university
route). Attacker Kali `192.168.56.10`, victim Kali `192.168.56.20` running
Apache 2.4.69 with the Suricata sensor co-located on the same interface.

## Ethics

All traffic was confined to the isolated lab network. No external system was
scanned or targeted at any point.
