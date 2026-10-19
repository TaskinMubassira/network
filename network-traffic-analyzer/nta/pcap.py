"""Minimal PCAP reader and packet decoder (Ethernet / raw IPv4, TCP, UDP).

Only the classic libpcap format is supported; save pcapng captures as
"Wireshark/tcpdump - pcap" or convert them with `editcap -F pcap in.pcapng out.pcap`.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_VLAN = 0x8100
PROTO_TCP, PROTO_UDP, PROTO_ICMP = 6, 17, 1

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10

# magic -> (byte order, timestamp divisor)
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


class PcapError(Exception):
    """The file is not a readable classic PCAP capture."""


@dataclass(frozen=True)
class Packet:
    ts: float
    src: str
    dst: str
    proto: int
    length: int
    sport: int = 0
    dport: int = 0
    flags: int = 0
    payload: bytes = b""

    @property
    def is_syn(self) -> bool:
        """A connection attempt: SYN set, ACK not set."""
        return self.proto == PROTO_TCP and bool(self.flags & TCP_SYN) and not self.flags & TCP_ACK


def read_pcap(path: Path) -> Iterator[Packet]:
    with path.open("rb") as f:
        yield from _read(f)


def _read(f: BinaryIO) -> Iterator[Packet]:
    header = f.read(24)
    if len(header) < 24 or header[:4] not in _MAGICS:
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise PcapError("pcapng is not supported; convert with: editcap -F pcap in.pcapng out.pcap")
        raise PcapError("not a pcap file")
    order, divisor = _MAGICS[header[:4]]
    linktype = struct.unpack(order + "I", header[20:24])[0] & 0x0FFFFFFF
    if linktype not in (LINKTYPE_ETHERNET, LINKTYPE_RAW):
        raise PcapError(f"unsupported link type {linktype}")

    record = struct.Struct(order + "IIII")
    while True:
        rh = f.read(16)
        if len(rh) < 16:
            return
        sec, frac, incl_len, orig_len = record.unpack(rh)
        data = f.read(incl_len)
        if len(data) < incl_len:
            return  # truncated capture: stop at the last complete packet
        pkt = decode(data, linktype, sec + frac / divisor, orig_len)
        if pkt is not None:
            yield pkt


def decode(data: bytes, linktype: int, ts: float, length: int) -> Packet | None:
    """Decode one frame; returns None for anything that is not IPv4."""
    if linktype == LINKTYPE_ETHERNET:
        if len(data) < 14:
            return None
        ethertype, offset = struct.unpack("!H", data[12:14])[0], 14
        if ethertype == ETHERTYPE_VLAN and len(data) >= 18:
            ethertype, offset = struct.unpack("!H", data[16:18])[0], 18
        if ethertype != ETHERTYPE_IPV4:
            return None
        data = data[offset:]

    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    proto = data[9]
    src = str(ipaddress.IPv4Address(data[12:16]))
    dst = str(ipaddress.IPv4Address(data[16:20]))
    total = struct.unpack("!H", data[2:4])[0]
    seg = data[ihl:total] if ihl < total <= len(data) else data[ihl:]

    if proto == PROTO_TCP and len(seg) >= 20:
        sport, dport = struct.unpack("!HH", seg[:4])
        hlen = (seg[12] >> 4) * 4
        return Packet(ts, src, dst, proto, length, sport, dport, seg[13], seg[hlen:])
    if proto == PROTO_UDP and len(seg) >= 8:
        sport, dport = struct.unpack("!HH", seg[:4])
        return Packet(ts, src, dst, proto, length, sport, dport, 0, seg[8:])
    return Packet(ts, src, dst, proto, length)


def dns_query_name(payload: bytes) -> str | None:
    """Return the first question name of a DNS query, or None if it is not one."""
    if len(payload) < 12 or payload[2] & 0x80:  # too short, or a response
        return None
    if struct.unpack("!H", payload[4:6])[0] < 1:
        return None
    labels, i = [], 12
    while i < len(payload):
        n = payload[i]
        if n == 0:
            return ".".join(labels).lower() if labels else None
        if n & 0xC0 or i + 1 + n > len(payload):  # compression pointer or truncated
            return None
        labels.append(payload[i + 1 : i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None
