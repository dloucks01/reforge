"""Robust pcap reading + reliable harvesting from a saved capture."""

from __future__ import annotations

import base64

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from reforge.attacks.stream_harvester import StreamHarvester
from reforge.core.pcaputil import read_frames, read_packets


def _write(path):
    tok = base64.b64encode(b"admin:hunter2").decode()
    req = f"POST /login HTTP/1.1\r\nHost: bank\r\nAuthorization: Basic {tok}\r\n\r\n".encode()
    pkts = [
        Ether() / IP(src="10.0.0.5", dst="93.1.2.3") / TCP(sport=5000, dport=80, seq=1, flags="PA") / req,
        Ether() / IP(src="10.0.0.9") / TCP(sport=22, seq=1, flags="PA") / b"SSH-2.0-OpenSSH_9\r\n",
    ]
    wrpcap(str(path), pkts)
    return req


def test_read_frames_returns_exact_bytes(tmp_path):
    p = tmp_path / "c.pcap"
    _write(p)
    frames = read_frames(p)
    assert len(frames) == 2
    # frames re-dissect with a TCP layer (not mangled to Raw)
    assert Ether(frames[0]).haslayer(TCP)
    assert read_packets(p)[0].haslayer(TCP)


def test_pcap_harvest_is_reliable(tmp_path):
    p = tmp_path / "loot.pcap"
    _write(p)
    h = StreamHarvester()
    found = []
    for raw in read_frames(p):
        found += h.add_frame(raw)
    assert any(c.kind == "http-basic" and c.username == "admin" for c in found)
