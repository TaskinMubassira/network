"""Traffic summary and detection rules."""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from typing import Iterable

from .pcap import PROTO_ICMP, PROTO_TCP, PROTO_UDP, Packet, dns_query_name


@dataclass
class Thresholds:
    scan_ports: int = 20          # distinct ports one source probes on one host
    sweep_hosts: int = 15         # distinct hosts one source probes on one port
    beacon_min: int = 6           # connections needed before judging regularity
    beacon_min_interval: float = 5.0   # seconds; faster is normal traffic, not a beacon
    beacon_max_jitter: float = 0.1     # max coefficient of variation of the intervals
    dns_max_name: int = 52        # longer query names look like encoded data
    dns_max_label: int = 30
    dns_entropy: float = 3.8      # bits per character of the longest label
    dns_subdomains: int = 30      # unique subdomains of one domain from one source


@dataclass
class Alert:
    rule: str
    severity: str
    src: str
    dst: str
    detail: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Summary:
    packets: int = 0
    bytes: int = 0
    start: float = 0.0
    end: float = 0.0
    protocols: Counter = field(default_factory=Counter)
    talkers: Counter = field(default_factory=Counter)        # src -> bytes
    conversations: Counter = field(default_factory=Counter)  # (src, dst) -> bytes
    ports: Counter = field(default_factory=Counter)          # "tcp/443" -> packets
    dns_queries: Counter = field(default_factory=Counter)

    @property
    def duration(self) -> float:
        return max(self.end - self.start, 0.0)


PROTO_NAMES = {PROTO_TCP: "tcp", PROTO_UDP: "udp", PROTO_ICMP: "icmp"}


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def base_domain(name: str) -> str:
    """Last two labels, a simple approximation of the registered domain."""
    return ".".join(name.split(".")[-2:])


def analyze(packets: Iterable[Packet], t: Thresholds | None = None) -> tuple[Summary, list[Alert]]:
    t = t or Thresholds()
    s = Summary()
    syn_ports: dict[tuple[str, str], set[int]] = defaultdict(set)
    syn_hosts: dict[tuple[str, int], set[str]] = defaultdict(set)
    conn_times: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    subdomains: dict[tuple[str, str], set[str]] = defaultdict(set)
    odd_names: dict[tuple[str, str], list[str]] = defaultdict(list)

    for p in packets:
        if s.packets == 0:
            s.start = p.ts
        s.packets += 1
        s.bytes += p.length
        s.start, s.end = min(s.start, p.ts), max(s.end, p.ts)
        name = PROTO_NAMES.get(p.proto, str(p.proto))
        s.protocols[name] += 1
        s.talkers[p.src] += p.length
        s.conversations[(p.src, p.dst)] += p.length
        if p.proto in (PROTO_TCP, PROTO_UDP):
            s.ports[f"{name}/{p.dport}"] += 1

        if p.is_syn:
            syn_ports[(p.src, p.dst)].add(p.dport)
            syn_hosts[(p.src, p.dport)].add(p.dst)
            conn_times[(p.src, p.dst, p.dport)].append(p.ts)

        if p.proto == PROTO_UDP and p.dport == 53:
            q = dns_query_name(p.payload)
            if q:
                s.dns_queries[q] += 1
                key = (p.src, base_domain(q))
                subdomains[key].add(q)
                if _odd_dns_name(q, t):
                    odd_names[key].append(q)

    alerts = _port_scans(syn_ports, t)
    alerts += _host_sweeps(syn_hosts, t)
    alerts += _beacons(conn_times, t)
    alerts += _dns_tunneling(subdomains, odd_names, t)
    order = {"high": 0, "medium": 1, "low": 2}
    alerts.sort(key=lambda a: (order[a.severity], a.rule, a.src))
    return s, alerts


def _port_scans(syn_ports, t: Thresholds) -> list[Alert]:
    return [
        Alert("port-scan", "high", src, dst, f"SYN to {len(ports)} distinct ports",
              {"ports": len(ports), "sample": sorted(ports)[:10]})
        for (src, dst), ports in syn_ports.items()
        if len(ports) >= t.scan_ports
    ]


def _host_sweeps(syn_hosts, t: Thresholds) -> list[Alert]:
    return [
        Alert("host-sweep", "medium", src, f"*:{port}", f"SYN to {len(hosts)} hosts on port {port}",
              {"hosts": len(hosts), "sample": sorted(hosts)[:10]})
        for (src, port), hosts in syn_hosts.items()
        if len(hosts) >= t.sweep_hosts
    ]


def _beacons(conn_times, t: Thresholds) -> list[Alert]:
    alerts = []
    for (src, dst, port), times in conn_times.items():
        if len(times) < t.beacon_min:
            continue
        times = sorted(times)
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(gaps)
        if mean < t.beacon_min_interval:
            continue
        jitter = statistics.pstdev(gaps) / mean
        if jitter <= t.beacon_max_jitter:
            alerts.append(Alert(
                "beaconing", "high", src, f"{dst}:{port}",
                f"{len(times)} connections every {mean:.1f}s (jitter {jitter:.0%})",
                {"connections": len(times), "interval": round(mean, 2), "jitter": round(jitter, 3)},
            ))
    return alerts


def _odd_dns_name(q: str, t: Thresholds) -> bool:
    """Very long names, or long random-looking labels, are typical of data encoded into DNS."""
    longest = max(q.split("."), key=len)
    return len(q) > t.dns_max_name or (
        len(longest) > t.dns_max_label and shannon_entropy(longest) >= t.dns_entropy
    )


def _dns_tunneling(subdomains, odd_names, t: Thresholds) -> list[Alert]:
    """One alert per (source, domain): high when many unique subdomains, medium for odd names only."""
    alerts = []
    for key in subdomains.keys() | odd_names.keys():
        src, domain = key
        unique, odd = len(subdomains.get(key, ())), odd_names.get(key, [])
        many = unique >= t.dns_subdomains
        if not (many or odd):
            continue
        reasons = []
        if many:
            reasons.append(f"{unique} unique subdomains")
        if odd:
            reasons.append(f"{len(odd)} long/random-looking names")
        alerts.append(Alert(
            "dns-tunneling", "high" if many else "medium", src, domain, ", ".join(reasons),
            {"unique_subdomains": unique, "odd_names": len(odd), "example": (odd or [""])[0]},
        ))
    return alerts
