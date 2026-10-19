"""Command line interface: analyse a PCAP and print a report."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from .detect import Alert, Summary, Thresholds, analyze
from .pcap import PcapError, read_pcap

EXIT_CLEAN, EXIT_ALERTS, EXIT_ERROR = 0, 1, 2


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _time(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def text_report(s: Summary, alerts: list[Alert], top: int) -> str:
    out = ["== Capture summary"]
    if s.packets == 0:
        return "== Capture summary\nNo IPv4 packets found."
    out.append(f"Packets:  {s.packets}   Bytes: {_human_bytes(s.bytes)}   Duration: {s.duration:.1f}s")
    out.append(f"Window:   {_time(s.start)} -> {_time(s.end)}")
    out.append("Protocols: " + ", ".join(f"{k} {v / s.packets:.0%}" for k, v in s.protocols.most_common()))

    out.append(f"\n== Top {top} talkers (bytes sent)")
    out += [f"  {ip:<16} {_human_bytes(b)}" for ip, b in s.talkers.most_common(top)]
    out.append(f"\n== Top {top} conversations")
    out += [f"  {a:<16} -> {b:<16} {_human_bytes(n)}" for (a, b), n in s.conversations.most_common(top)]
    out.append(f"\n== Top {top} destination ports")
    out += [f"  {port:<10} {n} packets" for port, n in s.ports.most_common(top)]
    if s.dns_queries:
        out.append(f"\n== Top {top} DNS queries")
        out += [f"  {n:>5}  {q}" for q, n in s.dns_queries.most_common(top)]

    out.append(f"\n== Alerts ({len(alerts)})")
    if not alerts:
        out.append("  none")
    for a in alerts:
        out.append(f"  [{a.severity.upper():<6}] {a.rule:<14} {a.src} -> {a.dst}  {a.detail}")
    return "\n".join(out)


def json_report(s: Summary, alerts: list[Alert], top: int) -> str:
    return json.dumps({
        "summary": {
            "packets": s.packets,
            "bytes": s.bytes,
            "start": s.start,
            "end": s.end,
            "duration": s.duration,
            "protocols": dict(s.protocols),
            "top_talkers": s.talkers.most_common(top),
            "top_conversations": [[a, b, n] for (a, b), n in s.conversations.most_common(top)],
            "top_ports": s.ports.most_common(top),
            "top_dns_queries": s.dns_queries.most_common(top),
        },
        "alerts": [a.to_dict() for a in alerts],
    }, indent=2)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nta",
        description="Network traffic analyzer: summarise a PCAP and detect port scans, "
                    "host sweeps, C2 beaconing and DNS tunneling.",
    )
    parser.add_argument("pcap", type=Path, help="capture file (classic pcap format)")
    parser.add_argument("--json", action="store_true", help="machine readable output")
    parser.add_argument("--top", type=int, default=5, help="rows per summary table (default 5)")
    parser.add_argument("--scan-ports", type=int, default=Thresholds.scan_ports,
                        help="distinct ports that count as a port scan")
    parser.add_argument("--sweep-hosts", type=int, default=Thresholds.sweep_hosts,
                        help="distinct hosts that count as a host sweep")
    parser.add_argument("--beacon-min", type=int, default=Thresholds.beacon_min,
                        help="connections needed before beaconing is judged")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    t = Thresholds(scan_ports=args.scan_ports, sweep_hosts=args.sweep_hosts, beacon_min=args.beacon_min)
    try:
        summary, alerts = analyze(read_pcap(args.pcap), t)
    except FileNotFoundError:
        print(f"error: {args.pcap} not found", file=sys.stderr)
        return EXIT_ERROR
    except PcapError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_ERROR

    report = json_report if args.json else text_report
    print(report(summary, alerts, args.top))
    return EXIT_ALERTS if alerts else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
