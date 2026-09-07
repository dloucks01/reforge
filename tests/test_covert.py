"""Covert channels: encode/decode round-trips, timing, and detection."""

from __future__ import annotations

from reforge.covert import detect, timing
from reforge.covert.channels import (
    DnsTunnelChannel,
    IcmpPayloadChannel,
    IpIdChannel,
    TcpIsnChannel,
)

SECRET = b"exfil: user=admin pass=hunter2 token=ABCDEF0123456789"


# ---- storage channels round-trip -------------------------------------------
def test_ip_id_channel_roundtrip():
    ch = IpIdChannel()
    assert ch.decode(ch.encode(SECRET)) == SECRET


def test_tcp_isn_channel_roundtrip():
    ch = TcpIsnChannel()
    assert ch.decode(ch.encode(SECRET)) == SECRET


def test_icmp_payload_channel_roundtrip():
    ch = IcmpPayloadChannel(chunk=16)
    pkts = ch.encode(SECRET)
    assert len(pkts) >= 3                      # spread across several packets
    assert ch.decode(pkts) == SECRET


def test_dns_tunnel_channel_roundtrip():
    ch = DnsTunnelChannel(domain="c2.example.net", label_len=20)
    queries = ch.encode(SECRET)
    assert ch.decode(queries) == SECRET


# ---- timing channel --------------------------------------------------------
def test_timing_channel_roundtrip():
    bits = "10110001"
    delays = timing.encode_timing(bits, unit=0.05)
    assert timing.decode_timing(delays, unit=0.05) == bits
    # reconstruct delays from timestamps
    ts = [0.0]
    for d in delays:
        ts.append(ts[-1] + d)
    assert timing.decode_timing(timing.delays_from_timestamps(ts), unit=0.05) == bits


# ---- detector --------------------------------------------------------------
def test_detect_dns_tunnel():
    queries = DnsTunnelChannel(domain="c2.example.net", label_len=30).encode(SECRET)
    findings = detect.detect(queries)
    assert any(f.channel == "dns-tunnel" for f in findings)


def test_detect_icmp_exfil():
    import os

    from scapy.layers.inet import ICMP, IP
    from scapy.packet import Raw

    pkts = [IP(dst="8.8.8.8") / ICMP() / Raw(os.urandom(48)) for _ in range(5)]
    findings = detect.detect(pkts)
    assert any(f.channel == "icmp-exfil" for f in findings)


def test_detect_clean_traffic_no_false_positive():
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import ICMP, IP, UDP

    benign = [IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="www.google.com")),
              IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="mail.corp.local")),
              IP() / ICMP() / (b"\x00" * 32)]                    # low-entropy ping
    assert detect.detect(benign) == []
