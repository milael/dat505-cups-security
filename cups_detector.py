"""DAT505 detection starter — implementation pending.

To implement: offline/live Scapy reader, parsing UDP 631 advertisements,
allowlist evaluation, anomalous IPP connection detection, rate thresholds,
and CSV/JSON alerts. Do not report assumed detections as verified.
"""
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="CUPS discovery detector (starter)")
    parser.add_argument("--pcap", help="PCAP to read offline")
    parser.add_argument("--interface", help="Interface to monitor live")
    parser.add_argument("--output", default="evidence/alerts.json")
    args = parser.parse_args()
    if bool(args.pcap) == bool(args.interface):
        parser.error("Choose exactly one of --pcap or --interface")
    raise SystemExit("Not yet implemented: Scapy parsing and alert export")


if __name__ == "__main__":
    main()
