
#!/usr/bin/env python3
"""DAT505: Offline CUPS discovery attack detector."""

import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, UDP, TCP, Raw, PcapReader

BROWSE_RE = re.compile(
    r'^0\s+3\s+'
    r'(?P<uri>https?://(?P<host>\d{1,3}(?:\.\d{1,3}){3})'
    r':(?P<port>\d{1,5})/printers/[^\s"]+)'
    r'\s+"[^"]*"\s+"[^"]*"\s*$'
)


def timestamp(value):
    return datetime.fromtimestamp(
        float(value), tz=timezone.utc
    ).isoformat()


def analyze(args):
    trusted = set(args.trusted_source)
    alerts = []
    advertisements = []
    recent = defaultdict(deque)
    seen_syns = set()

    def alert(packet, rule, severity, detail):
        alerts.append({
            "timestamp": timestamp(packet.time),
            "rule": rule,
            "severity": severity,
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "detail": detail,
        })

    with PcapReader(args.pcap) as reader:
        for packet in reader:
            if IP not in packet:
                continue

            ip = packet[IP]
            now = float(packet.time)

            # Legacy CUPS printer advertisements.
            if UDP in packet and packet[UDP].dport == 631:
                if ip.dst != args.victim:
                    continue

                payload = bytes(packet[UDP].payload)
                message = payload.decode(
                    "utf-8", errors="replace"
                ).strip()

                match = BROWSE_RE.fullmatch(message)

                if match:
                    host = match.group("host")
                    port = int(match.group("port"))

                    try:
                        ipaddress.IPv4Address(host)
                    except ipaddress.AddressValueError:
                        match = None

                    if not 1 <= port <= 65535:
                        match = None

                if not match:
                    alert(
                        packet, "D04", "medium",
                        "Malformed or unexpected CUPS browse message"
                    )
                else:
                    host = match.group("host")
                    port = int(match.group("port"))

                    untrusted = ip.src not in trusted

                    advertisements.append({
                        "time": now,
                        "source": ip.src,
                        "host": host,
                        "port": port,
                        "untrusted": untrusted,
                    })

                    if untrusted:
                        alert(
                            packet, "D01", "high",
                            f"Untrusted discovery source {ip.src} "
                            f"advertised {host}:{port}"
                        )

                # Sliding-window discovery burst detection.
                window = recent[ip.src]
                window.append(now)

                while window and now - window[0] > args.window:
                    window.popleft()

                if len(window) == args.threshold:
                    alert(
                        packet, "D03", "medium",
                        f"{len(window)} advertisements within "
                        f"{args.window:g} seconds"
                    )

            # New TCP connections from victim to advertised IPP.
            if TCP in packet and ip.src == args.victim:
                tcp = packet[TCP]

                if tcp.flags & 0x02 and not tcp.flags & 0x10:
                    syn_key = (
                        ip.src, ip.dst,
                        tcp.sport, tcp.dport, tcp.seq
                    )

                    # Avoid duplicate SYN observations.
                    if syn_key in seen_syns:
                        continue

                    seen_syns.add(syn_key)

                    for ad in reversed(advertisements):
                        if (
                            ad["untrusted"]
                            and ad["host"] == ip.dst
                            and ad["port"] == tcp.dport
                            and 0 <= now - ad["time"] <= args.callback_window
                        ):
                            alert(
                                packet, "D02", "high",
                                "Victim initiated TCP connection "
                                f"to {ip.dst}:{tcp.dport} following "
                                f"untrusted discovery from {ad['source']}"
                            )
                            break

    return alerts


def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious CUPS discovery from PCAP"
    )
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--victim", required=True)
    parser.add_argument(
        "--trusted-source", action="append", default=[]
    )
    parser.add_argument(
        "--threshold", type=int, default=5
    )
    parser.add_argument(
        "--window", type=float, default=10.0
    )
    parser.add_argument(
        "--callback-window", type=float, default=10.0
    )
    parser.add_argument(
        "--json", default="evidence/logs/detections.json"
    )
    parser.add_argument(
        "--csv", default="evidence/logs/detections.csv"
    )

    args = parser.parse_args()

    if (
        args.threshold < 1
        or args.window <= 0
        or args.callback_window <= 0
    ):
        parser.error("Threshold and windows must be positive")

    alerts = analyze(args)

    json_path = Path(args.json)
    csv_path = Path(args.csv)

    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    json_path.write_text(
        json.dumps(alerts, indent=2), encoding="utf-8"
    )

    fields = [
        "timestamp", "rule", "severity",
        "src", "dst", "detail"
    ]

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(alerts)

    for item in alerts:
        print(
            f"[{item['severity'].upper()}] "
            f"{item['rule']}: {item['detail']}"
        )

    print(f"Total alerts: {len(alerts)}")
    print(f"JSON: {json_path}")
    print(f"CSV: {csv_path}")


if __name__ == "__main__":
    main()

