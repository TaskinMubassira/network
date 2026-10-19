"""Build synthetic captures for tests and the demo sample.

Run `python -m nta.synth samples/demo.pcap` to write a capture that contains
normal web/DNS traffic plus a port scan, a host sweep, a beacon and DNS tunneling.
"""

from __future__ import annotations

import base64
import ipaddress
import random
import struct
import sys
from pathlib import Path

from .pcap import PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_PSH, TCP_SYN

ETH_HEADER = b"\x00\x11\x22\x33\x44\x55" + b"\x66\x77\x88\x99\xaa\xbb" + b"\x08\x00"


def tcp(src: str, dst: str, sport: int, dport: int, flags: int = TCP_SYN, payload: bytes = b"") -> bytes:
    seg = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload
    return _ip(src, dst, PROTO_TCP, seg)


def udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return _ip(src, dst, PROTO_UDP, seg)


def dns_query(name: str, txid: int = 0x1234) -> bytes:
    q = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def _ip(src: str, dst: str, proto: int, seg: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 0, 0, 64, proto, 0,
        ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed,
    )
    return ETH_HEADER + header + seg


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    with path.open("wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in sorted(frames, key=lambda x: x[0]):
            sec = int(ts)
            f.write(struct.pack("<IIII", sec, int(round((ts - sec) * 1_000_000)), len(frame), len(frame)))
            f.write(frame)


def demo_frames(seed: int = 7) -> list[tuple[float, bytes]]:
    rng = random.Random(seed)
    t0 = 1_760_000_000.0
    frames: list[tuple[float, bytes]] = []
    clients = [f"192.168.1.{i}" for i in range(10, 20)]

    # Normal traffic: web browsing and DNS lookups at irregular times.
    for _ in range(400):
        c, ts = rng.choice(clients), t0 + rng.uniform(0, 600)
        server = rng.choice(["142.250.183.14", "104.16.132.229", "151.101.1.69"])
        sport = rng.randint(40000, 60000)
        frames.append((ts, tcp(c, server, sport, 443)))
        frames.append((ts + 0.05, tcp(server, c, 443, sport, TCP_SYN | TCP_ACK)))
        frames.append((ts + 0.1, tcp(c, server, sport, 443, TCP_PSH | TCP_ACK, b"x" * rng.randint(100, 1400))))
    for _ in range(150):
        name = rng.choice(["www.google.com", "github.com", "cdn.jsdelivr.net", "api.github.com"])
        frames.append((t0 + rng.uniform(0, 600), udp(rng.choice(clients), "192.168.1.1", rng.randint(40000, 60000), 53, dns_query(name))))

    # Port scan: one host probes 200 ports on the file server.
    for i, port in enumerate(range(1, 201)):
        frames.append((t0 + 100 + i * 0.01, tcp("192.168.1.66", "192.168.1.5", 51515, port)))

    # Host sweep: the same attacker looks for SMB across the subnet.
    for i in range(1, 41):
        frames.append((t0 + 200 + i * 0.02, tcp("192.168.1.66", f"192.168.1.{100 + i}", 51600 + i, 445)))

    # Beaconing: an infected client calls its C2 server every 30 s with ~1 s jitter.
    for i in range(20):
        frames.append((t0 + 5 + i * 30 + rng.uniform(-1, 1), tcp("192.168.1.23", "203.0.113.50", 50000 + i, 8443)))

    # DNS tunneling: data exfiltrated as base32 chunks in subdomains.
    secret = bytes(rng.getrandbits(8) for _ in range(1200))
    for i in range(0, len(secret), 30):
        chunk = base64.b32encode(secret[i : i + 30]).decode().rstrip("=").lower()
        frames.append((t0 + 300 + i * 0.1, udp("192.168.1.42", "192.168.1.1", 53000, 53, dns_query(f"{chunk}.x.exfil-example.net"))))

    return frames


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/demo.pcap")
    out.parent.mkdir(parents=True, exist_ok=True)
    frames = demo_frames()
    write_pcap(out, frames)
    print(f"wrote {len(frames)} packets to {out}")
