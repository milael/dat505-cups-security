"""DAT505 attack tool starter — implementation pending.

Develop your own Scapy-based CUPS discovery packets and run only against the
isolated course lab. Capture packets and verify victim callbacks separately.
"""
import argparse


def main() -> None:
    parser = argparse.ArgumentParser(description="CUPS discovery lab (starter)")
    parser.add_argument("--victim", required=True, help="Isolated lab victim IPv4")
    parser.add_argument("--printer-host", required=True, help="Isolated lab printer IPv4")
    parser.add_argument("--printer-port", type=int, default=631)
    parser.add_argument("--pcap", default="pcap_files/sent-discovery.pcap")
    args = parser.parse_args()
    raise SystemExit("Not yet implemented: construct and send Scapy UDP/631 discovery frames")


if __name__ == "__main__":
    main()
