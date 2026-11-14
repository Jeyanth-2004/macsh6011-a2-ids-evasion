# Results — MACSH6011 A2 IDS Evasion

Engine: **Suricata 8.0.8 RELEASE**. All runs offline (`suricata -r ... -k none`).
Constant payload: `GET /malicious_shell.php`. Signatures: sid 1000001 (normalised
`http.uri`), sid 1000002 (raw TCP `content`).

## Results matrix

| # | Technique | Category | Baseline | After evasion | Countermeasure | After CM | FP (benign) |
|---|-----------|----------|:---:|:---:|-----------|:---:|:---:|
| T1 | IP-fragment overlap | Fragmentation | 1000001 + 1000002 | none (evaded) | `host-os-policy: bsd-right` for victim | 1000001 + 1000002 | 0 |
| T2 | TCP segment overlap | Segment overlap | 1000001 + 1000002 | none (evaded) | `check-overlap-different-data: true` + sid 1000003 | 1000003 | 0 |
| T3 | URL encoding (`%5F`) | Payload encoding | 1000001 + 1000002 | 1000001 only (raw blinded) | anchor signatures to normalised buffers | 1000001 | 0 |
| T4 | Low-and-slow + fragmentation | Timing × fragmentation (advanced) | 1000001 + 1000002 | none (evaded) | `--set defrag.timeout=300` | 1000001 + 1000002 | 0 |

All four techniques restored. FP measured on `benign2.pcap` (20 requests incl.
7 legitimate identical-data TCP retransmissions): **0 alerts** with every
countermeasure active.

## Per-technique mechanism and commands

### Baseline
```
sudo suricata -c suricata.yaml -S local.rules -r baseline.pcap -l out -k none
```
→ sid 1000001 and sid 1000002 both fire. Detection confirmed before evasion.

### T1 — IP fragmentation overlap
Overlapping IP fragments carry conflicting bytes over the `malicious` token.
- Malicious-first overlap → **detected** (Suricata keeps first-arriving bytes).
- Benign-first overlap (`t1.pcap`) → **evaded** (default `host-os-policy: windows [0.0.0.0/0]` favours the first fragment).
- **Countermeasure:** declare the victim under `bsd-right` (favours later fragment, as the real target would):
  `host-os-policy: bsd-right: ["192.168.56.20"]` → detection restored on the same pcap.
- Mechanism: IP defragmentation overlap-resolution policy (Ptacek–Newsham).

### T2 — TCP segment overlap
A full benign request, then a short malicious segment overwriting the token at
an overlapping sequence number (`t2.pcap`) → **evaded**. Suricata's stream
reassembler keeps the first (benign) segment and parses a benign URL.
- `host-os-policy` change alone did **not** restore detection (stream engine
  keeps first-seen segment regardless of policy).
- **Countermeasure that works:** enable `stream.reassembly.check-overlap-different-data: true`
  (disabled by default) and add a rule on `stream-event:reassembly_overlap_different_data`
  (sid 1000003). sid 1000003 then fires on the T2 pcap → **detection restored**.
- This detects the *technique* (conflicting overlapping data), not the payload,
  so it generalises. It does **not** fire on legitimate identical-data
  retransmissions (verified in the FP test), so FP cost = 0.
- Key insight: the gap is a configuration default, not a fundamental limit — a
  secure-by-default build would ship this check enabled.

### T3 — URL encoding
`malicious%5Fshell.php` (`%5F` = `_`). Raw rule (1000002) blinded; normalised
rule (1000001) still fires because Suricata percent-decodes the URI before the
`http.uri` buffer.
- **Countermeasure:** author content signatures against normalised buffers
  (structural, zero cost). Demonstrated live via curl as well as offline.

### T4 — Low-and-slow + fragmentation (advanced)
Fragments spaced 75 s apart in capture time (`t4.pcap`), exceeding the 60 s
`defrag.timeout`; partial reassembly expires before the last fragment → **evaded**.
- **Countermeasure:** `--set defrag.timeout=300` → detection restored on the same pcap.
- **Cost:** a longer timeout holds partial reassemblies longer, enlarging the
  memory-exhaustion / DoS surface (detection vs resource trade-off).

### False positives
20 well-formed benign requests (`benign2.pcap`), of which 7 carried legitimate
identical-data TCP retransmissions and several had paths containing suspicious
substrings (`shell`, `malicious`), processed through the fully hardened
configuration (`bsd-right` + `check-overlap-different-data` + `defrag.timeout=300`
+ custom rules): **0 alerts.** The overlap countermeasure correctly fired on
T2's different-data overlap but stayed silent on identical-data retransmissions.
Measured false-positive cost of the deployed countermeasures = 0.
(`benign.pcap` is the earlier 10-request corpus; `benign2.pcap` is the stress corpus.)

## Config changes from stock suricata.yaml
- `host-os-policy`: victim `192.168.56.20` moved from default `windows` to `bsd-right` (T1 countermeasure).
- `stream.reassembly.check-overlap-different-data`: commented-out default → `true` (T2 countermeasure).
- `defrag.timeout`: 60 → 300 (T4 countermeasure; applied via `--set` at runtime).
