# DAT505 Assignment 2 — CUPS Printer Discovery and Attack Detection

**Status: experiments completed and captured on 16 November 2026.** This is an isolated educational security laboratory, not a remote-code-execution demonstration.

**Repository:** https://github.com/milael/dat505-cups-security  
**Main report:** `DAT505_Assignment2_Report.pdf` (submit the PDF separately if required by the course).

## Objective

Demonstrate that legacy CUPS browse advertisements sent to a vulnerable `cups-browsed` instance can induce an outbound printer connection; implement a Scapy packet generator and offline PCAP detector; evaluate altered discovery advertisements and a source-specific UDP/631 firewall mitigation. All experiments were performed on isolated Docker networking, not third-party systems.

## Architecture and prerequisites

| Role | Container | Address observed | Notes |
| --- | --- | --- | --- |
| Attacker | `dat505-cups-attacker` | `172.19.0.3` | Python 3.12, Scapy 2.8, tcpdump, iptables tooling |
| Victim | `dat505-cups-victim` | `172.19.0.2` | `vulhub/cups-browsed:2.0.1`, AMD64 emulated on ARM64 Mac |
| Software printer | `dat505-cups-printer` | `172.19.0.4` | `ippeveprinter`, TCP 8631, DNS-SD disabled in printer command |

Docker Compose uses an `internal: true` bridge and does not publish victim ports. **Addresses are observations from this run, not guaranteed after recreation.** Docker Desktop and Compose are prerequisites. The attacker and printer images are built locally.

```bash
docker build -t dat505-scapy-attacker -f docker/attacker/Dockerfile .
docker build -t dat505-ipp-printer -f docker/printer/Dockerfile .
docker compose -f lab-compose.yml up -d
docker compose -f lab-compose.yml ps
```

To verify the IPP emulator: 

```bash
docker run --rm --network container:dat505-cups-attacker \
  --entrypoint ipptool dat505-ipp-printer -tv \
  ipp://172.19.0.4:8631/ipp/print \
  /usr/share/cups/ipptool/get-printer-attributes.test
```

The example IP addresses assume the documented run. Check actual addresses using `docker inspect` and substitute if needed. Direct HTTP `GET /` may give `400 Bad Request`; use `ipptool` for an actual IPP request.

## Attack implementation

`cups_attack.py` builds `IP/UDP/Raw` Scapy packets addressed to UDP/631 containing the legacy discovery announcement. It supports victim address, advertised host, advertised port and path, location, info, count (1–20), rate, sent-PCAP, and JSONL log output.

```bash
docker exec dat505-cups-attacker python /workspace/cups_attack.py \
  --victim 172.19.0.2 --printer-ip 172.19.0.4 \
  --printer-port 8631 --count 1 \
  --pcap pcap_files/attack/E02_sent.pcap \
  --log evidence/logs/E02_attack.jsonl
```

Default advertised URI: `http://172.19.0.4:8631/printers/DAT505-Lab-Printer`. The `/printers/` URI path was required to trigger a callback in this lab; `/ipp/print` variants were received but rejected by the discovery parser. **Sent-packet PCAPs do not establish victim reception:** the separately captured victim-side PCAPs are authoritative.

For capture, run a temporary tcpdump container in the victim namespace **before** sending traffic:

```bash
docker run --rm --network container:dat505-cups-victim \
  --cap-add NET_RAW --cap-add NET_ADMIN \
  -v "$(pwd):/workspace" dat505-scapy-attacker \
  tcpdump -i eth0 -s 0 -nn \
  -w /workspace/pcap_files/attack/example.pcap \
  'udp port 631 or tcp port 8631 or tcp port 8632'
```

## Detection implementation

`cups_detector.py` reads offline PCAPs using `PcapReader` and exports JSON and CSV alerts. Four rules:

- **D01:** syntactically expected browse announcement from a source not in the supplied allowlist.
- **D02:** SYN initiated by the victim toward the advertised destination shortly after untrusted discovery. Identical SYN sequences are deduplicated.
- **D03:** rate threshold (default: five announcements in ten seconds, per sender).
- **D04:** unexpected or malformed legacy browse announcement format, including a path the detector does not recognize.

```bash
docker exec dat505-cups-attacker python /workspace/cups_detector.py \
  --pcap pcap_files/attack/E02_cli_test.pcap \
  --victim 172.19.0.2 --trusted-source 172.19.0.4 \
  --json evidence/logs/E02_detections.json \
  --csv evidence/logs/E02_detections.csv
```

**Limitations:** The detector assumes the strict `0 3 http(s)://IPv4:port/printers/...` grammar, manually supplied victim and allowlist, and a time-window correlation, which can produce false positives or miss valid CUPS traffic. It cannot prove printer registration or code execution, and does not implement general IPP parsing. The source allowlist is illustrative and does not represent independently verified trusted printer-discovery infrastructure.

## Verified experiments

| ID | Scenario and key observation | Captured file | Detector result |
| --- | --- | --- | --- |
| E00 | Direct normal `Get-Printer-Attributes` succeeded (`successful-ok`); 24 packets | `pcap_files/normal/E00_ipp_baseline.pcap` | 0 alerts |
| E01 | `/ipp/print` browse URIs rejected; `/printers/DAT505-Lab-Printer` triggered victim TCP callback | `pcap_files/attack/E01_printers_path.pcap` | Not labeled by current detector outputs |
| E02 | Parameterized Scapy advertisement, victim initiated TCP to 172.19.0.4:8631 | `pcap_files/attack/E02_cli_test.pcap` | D01 + D02 (2) |
| E03 | Changed advertised TCP port to 8632; victim sent SYN to that port | `pcap_files/attack/E03_modified_port.pcap` | D01 + D02 (2) |
| E04 | Unexpected URI path `/ipp/print` | `pcap_files/attack/E04_invalid_path.pcap` | D04 (1) |
| E05 | Five announcements at 0.2 s spacing | `pcap_files/attack/E05_burst.pcap` | D01 x5, D02 x5, D03 x1 (11) |
| E06 | Source-specific UDP/631 DROP rule matched one packet; no victim TCP callback observed | `pcap_files/mitigation/E06_after_firewall.pcap` | D01 only (1) |

Evidence: `evidence/logs/` contains original attack JSONL, detector JSON/CSV, victim/printer logs, and `E06_firewall_counters.txt`. The E06 counter recorded one dropped packet (114 bytes); the rule was removed after the test. The failed E01 URI variants are preserved rather than omitted.

## Mitigation, analysis, and caveats

Mitigation was an `iptables` INPUT DROP on the victim's network namespace, specifically `-s 172.19.0.3 -p udp --dport 631`. Before mitigation (E02) the advertisement resulted in a TCP callback; with this rule applied (E06), the victim-side capture still observed the inbound datagram but no outbound TCP session. The detector correspondingly reported D01 but not D02. This documents one controlled before/after outcome; it does not prove comprehensive resistance to CUPS exploitation.

Only two kinds of benign/negative examples were tested: direct IPP traffic (E00) and unsupported browse format (E04). We do **not** claim production accuracy, numerical false-positive rate, or zero false negatives. DNS-SD was disabled for the software printer, so E00 is a normal IPP protocol baseline rather than an automatic-discovery baseline.

## Safety and references

Never run outside an authorized isolated environment or publish vulnerable port 631 on the host. Stop the lab with `docker compose -f lab-compose.yml down` when finished.

- Vulhub environment: https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177 (path retains legacy/rejected CVE identifier).
- OpenPrinting security advisory: https://github.com/OpenPrinting/cups-browsed/security/advisories/GHSA-rj88-6mr5-rcw8
- Scapy project: https://scapy.net/
