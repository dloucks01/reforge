"""fuzzing.corpus: build fuzzing seeds from a pcap, optionally layer-filtered."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from reforge.fuzzing.corpus import seeds_from_pcap


def _write(tmp_path):
    pkts = ([Ether() / IP(dst=f"10.0.0.{i}") / TCP(dport=80) / b"tcp" for i in range(3)]
            + [Ether() / IP() / UDP(dport=53) / b"udp" for _ in range(2)])
    p = tmp_path / "corpus.pcap"
    wrpcap(str(p), pkts)
    return p


def test_seeds_all_packets(tmp_path):
    seeds = seeds_from_pcap(_write(tmp_path))
    assert len(seeds) == 5 and all(isinstance(s, bytes) for s in seeds)


def test_seeds_layer_filter(tmp_path):
    tcp = seeds_from_pcap(_write(tmp_path), bpf_layer="TCP")
    udp = seeds_from_pcap(_write(tmp_path), bpf_layer="UDP")
    assert len(tcp) == 3 and len(udp) == 2
    assert all(b"tcp" in s for s in tcp)


def test_seeds_limit(tmp_path):
    assert len(seeds_from_pcap(_write(tmp_path), limit=2)) == 2
