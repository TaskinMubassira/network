# Network Traffic Analyzer

A small Python tool for network analysts. It reads a packet capture (`.pcap` from Wireshark or tcpdump), summarises the traffic and flags suspicious behaviour:

| Rule | What it looks for | Why it matters |
|---|---|---|
| `port-scan` | One host sending SYNs to many ports on another host | Reconnaissance before an attack |
| `host-sweep` | One host sending SYNs to the same port on many hosts | Searching the network for a service (e.g. SMB/445) to exploit or spread through |
| `beaconing` | Connections to the same server at very regular intervals | Malware checking in with its command and control (C2) server |
| `dns-tunneling` | Many unique or long, random-looking subdomains of one domain | Data exfiltration or C2 hidden inside DNS queries |

The PCAP parser is written from scratch with the standard library, so there are no dependencies.

## Usage

```bash
# Create a demo capture with normal traffic plus four attacks
python -m nta.synth samples/demo.pcap

# Analyse it (exit code 0 = no alerts, 1 = alerts, 2 = error)
python -m nta samples/demo.pcap
```

Example output (shortened):

```
== Capture summary
Packets:  1650   Bytes: ...   Duration: ...
Protocols: tcp 88%, udp 12%
...

== Alerts (4)
  [HIGH  ] beaconing      192.168.1.23 -> 203.0.113.50:8443  20 connections every 30.0s (jitter 3%)
  [HIGH  ] dns-tunneling  192.168.1.42 -> exfil-example.net  40 unique subdomains, 40 long/random-looking names
  [HIGH  ] port-scan      192.168.1.66 -> 192.168.1.5  SYN to 200 distinct ports
  [MEDIUM] host-sweep     192.168.1.66 -> *:445  SYN to 40 hosts on port 445
```

Options: `--json` for machine readable output, `--top N` for longer tables, and `--scan-ports`, `--sweep-hosts`, `--beacon-min` to tune detection thresholds.

To analyse your own traffic, capture with `tcpdump -i eth0 -w capture.pcap` or save from Wireshark as *Wireshark/tcpdump - pcap*. pcapng files can be converted with `editcap -F pcap in.pcapng out.pcap`.

## How the detections work

- **Port scan / host sweep:** only connection attempts (SYN without ACK) are counted, so normal replies and established traffic do not trigger them.
- **Beaconing:** for every (source, destination, port) the gaps between connection attempts are measured. Humans browse irregularly; malware on a timer does not. An alert needs at least 6 connections, an average gap of 5 s or more, and a coefficient of variation (standard deviation / mean) of 10% or less, so small jitter added by malware is still caught.
- **DNS tunneling:** each query is grouped by source and domain. Many unique subdomains, names longer than 52 characters, or labels longer than 30 characters with high Shannon entropy (≥ 3.8 bits per character) indicate data encoded into DNS.

## Limitations

- IPv4 only, classic pcap only (no pcapng, no IPv6).
- Signature-free heuristics: CDNs, backups or update checks can look like beaconing, so treat alerts as leads to investigate, not verdicts.
- Encrypted payloads are not inspected; detection is based on metadata (who, when, how often).

## Tests

```bash
pip install pytest
python -m pytest
```

## Project structure

```
nta/
  pcap.py     PCAP reader and Ethernet/IPv4/TCP/UDP/DNS decoding
  detect.py   traffic summary and detection rules
  cli.py      text and JSON reports
  synth.py    builds synthetic captures for tests and the demo
tests/
  test_nta.py
```
