# DAT505 Assignment 2 — CUPS Printer Discovery and Detection

Individual educational security laboratory. **Status: setup scaffold; experiments have not yet been executed.**

## Scope

Demonstrate printer-discovery trust behaviour against the supplied vulnerable `cups-browsed` container using Scapy, build a Scapy detection tool, run three packet variations, and compare one mitigation before and after. No RCE or live/public targets.

## Source environment

- https://github.com/vulhub/vulhub/tree/master/cups-browsed/CVE-2024-47177
- The folder name uses the rejected CVE-2024-47177 identifier.

## Quick setup (isolated lab only)

1. Create an isolated Docker network and run the Vulhub victim inside it. Verify image architecture and UDP/631 reachability from the attacker container.
2. Run an IPP simulator inside the same network; record its actual IP and port.
3. Install `requirements.txt` in the attacker container and use `tcpdump` to capture discovery and IPP traffic.
4. Implement `cups_attack.py` and `cups_detector.py`, then collect labeled baseline and attack PCAPs.
5. Write all observed results and mitigation comparison into `evidence/` and the final PDF.

## Experiment evidence checklist

| ID | Test | PCAP | Logs/screenshots | Result |
| --- | --- | --- | --- | --- |
| E0 | Normal printer discovery | pending | pending | Not run |
| E1 | Unauthorized advertisement | pending | pending | Not run |
| E2 | Changed advertised IP | pending | pending | Not run |
| E3 | Changed advertised port | pending | pending | Not run |
| E4 | Malformed/unexpected field | pending | pending | Not run |
| E5 | Detector evaluation | pending | pending | Not run |
| E6 | Mitigation before/after | pending | pending | Not run |

## Ethics

Run only in isolated, owned Docker/VM networking. Do not expose vulnerable UDP/631 to a public or university network.
