import json
import struct

import pytest

from nta.cli import EXIT_ALERTS, EXIT_CLEAN, EXIT_ERROR, main
from nta.detect import analyze, shannon_entropy
from nta.pcap import PROTO_TCP, PROTO_UDP, TCP_ACK, TCP_SYN, PcapError, decode, dns_query_name, read_pcap
from nta.synth import demo_frames, dns_query, tcp, udp, write_pcap


def rules(alerts):
    return {a.rule for a in alerts}


def capture(tmp_path, frames, name="cap.pcap"):
    path = tmp_path / name
    write_pcap(path, frames)
    return path


def test_decode_tcp_and_udp():
    p = decode(tcp("10.0.0.1", "10.0.0.2", 1234, 80, TCP_SYN), 1, 1.0, 60)
    assert (p.src, p.dst, p.proto, p.sport, p.dport, p.is_syn) == ("10.0.0.1", "10.0.0.2", PROTO_TCP, 1234, 80, True)
    assert not decode(tcp("10.0.0.2", "10.0.0.1", 80, 1234, TCP_SYN | TCP_ACK), 1, 1.0, 60).is_syn
    u = decode(udp("10.0.0.1", "8.8.8.8", 5000, 53, dns_query("example.com")), 1, 1.0, 80)
    assert u.proto == PROTO_UDP and dns_query_name(u.payload) == "example.com"


def test_decode_ignores_non_ipv4_and_short_frames():
    arp = b"\xff" * 12 + b"\x08\x06" + b"\x00" * 28
    assert decode(arp, 1, 0.0, 42) is None
    assert decode(b"\x00" * 10, 1, 0.0, 10) is None


def test_dns_response_is_not_a_query():
    response = bytearray(dns_query("example.com"))
    response[2] |= 0x80
    assert dns_query_name(bytes(response)) is None


def test_read_round_trip_and_bad_files(tmp_path):
    path = capture(tmp_path, [(10.5, tcp("1.1.1.1", "2.2.2.2", 1, 2))])
    packets = list(read_pcap(path))
    assert len(packets) == 1 and packets[0].ts == pytest.approx(10.5)

    junk = tmp_path / "junk.pcap"
    junk.write_bytes(b"not a capture at all....")
    with pytest.raises(PcapError):
        list(read_pcap(junk))
    ng = tmp_path / "x.pcapng"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 30)
    with pytest.raises(PcapError, match="pcapng"):
        list(read_pcap(ng))


def test_truncated_capture_keeps_complete_packets(tmp_path):
    path = capture(tmp_path, [(1.0, tcp("1.1.1.1", "2.2.2.2", 1, 2)), (2.0, tcp("1.1.1.1", "2.2.2.2", 1, 3))])
    path.write_bytes(path.read_bytes()[:-10])
    assert len(list(read_pcap(path))) == 1


def test_port_scan():
    pkts = [decode(tcp("10.0.0.9", "10.0.0.5", 4444, port), 1, i * 0.01, 60) for i, port in enumerate(range(1, 31))]
    _, alerts = analyze(pkts)
    assert [a.rule for a in alerts] == ["port-scan"]
    assert alerts[0].evidence["ports"] == 30


def test_host_sweep():
    pkts = [decode(tcp("10.0.0.9", f"10.0.1.{i}", 4000 + i, 445), 1, i * 0.01, 60) for i in range(20)]
    _, alerts = analyze(pkts)
    assert rules(alerts) == {"host-sweep"}


def test_beaconing_regular_but_not_random():
    regular = [decode(tcp("10.0.0.7", "203.0.113.5", 5000 + i, 443), 1, i * 60.0, 60) for i in range(10)]
    _, alerts = analyze(regular)
    assert rules(alerts) == {"beaconing"} and alerts[0].evidence["interval"] == pytest.approx(60)

    irregular_times = [0, 3, 50, 52, 200, 201, 480, 700, 705, 900]
    irregular = [decode(tcp("10.0.0.7", "203.0.113.5", 5000 + i, 443), 1, float(ts), 60) for i, ts in enumerate(irregular_times)]
    assert analyze(irregular)[1] == []


def test_dns_tunneling_and_normal_dns():
    normal = [decode(udp("10.0.0.3", "10.0.0.1", 5000, 53, dns_query(n)), 1, float(i), 70)
              for i, n in enumerate(["www.google.com", "mail.google.com", "github.com"] * 20)]
    assert analyze(normal)[1] == []

    tunnel = [decode(udp("10.0.0.3", "10.0.0.1", 5000, 53, dns_query(f"q{i}x7k2p9zq4m8w1v6b3n5c0r.evil.net")), 1, float(i), 90)
              for i in range(40)]
    _, alerts = analyze(tunnel)
    assert [(a.rule, a.severity, a.dst) for a in alerts] == [("dns-tunneling", "high", "evil.net")]


def test_entropy():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_demo_capture_finds_every_attack_and_nothing_else(tmp_path):
    path = capture(tmp_path, demo_frames())
    summary, alerts = analyze(read_pcap(path))
    assert summary.packets > 1000
    found = {(a.rule, a.src) for a in alerts}
    assert found == {
        ("port-scan", "192.168.1.66"),
        ("host-sweep", "192.168.1.66"),
        ("beaconing", "192.168.1.23"),
        ("dns-tunneling", "192.168.1.42"),
    }


def test_cli_text_and_json(tmp_path, capsys):
    path = capture(tmp_path, demo_frames())
    assert main([str(path)]) == EXIT_ALERTS
    out = capsys.readouterr().out
    assert "== Capture summary" in out and "port-scan" in out

    assert main([str(path), "--json"]) == EXIT_ALERTS
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["packets"] > 1000 and len(data["alerts"]) == 4


def test_cli_clean_and_errors(tmp_path):
    clean = capture(tmp_path, [(1.0, tcp("1.1.1.1", "2.2.2.2", 1, 443))])
    assert main([str(clean)]) == EXIT_CLEAN
    assert main([str(tmp_path / "missing.pcap")]) == EXIT_ERROR
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(struct.pack("<I", 0) * 6)
    assert main([str(bad)]) == EXIT_ERROR
