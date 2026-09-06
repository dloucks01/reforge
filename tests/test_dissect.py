"""Dissection view tests — pure functions, no capture/root needed."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.dissect import scapy_tree


def _pkt():
    return Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66") / IP(
        src="10.0.0.1", dst="10.0.0.2"
    ) / TCP(sport=1234, dport=80)


def test_summarize_basic():
    row = scapy_tree.summarize(_pkt(), index=3, ts=1.5)
    assert row.index == 3
    assert row.src == "10.0.0.1"
    assert row.dst == "10.0.0.2"
    assert row.proto == "TCP"
    assert row.length > 0
    assert "TCP" in row.info


def test_top_protocol_udp():
    pkt = Ether() / IP() / UDP(dport=53)
    assert scapy_tree.top_protocol(pkt) == "UDP"


def test_endpoints_arp():
    from scapy.layers.l2 import ARP

    pkt = Ether() / ARP(psrc="192.168.0.1", pdst="192.168.0.2")
    src, dst = scapy_tree.endpoints(pkt)
    assert src == "192.168.0.1"
    assert dst == "192.168.0.2"


def test_to_tree_layers_and_fields():
    tree = scapy_tree.to_tree(_pkt())
    names = [layer.name for layer in tree]
    assert "Ethernet" in names
    assert "IP" in names
    assert "TCP" in names
    ip_layer = next(layer for layer in tree if layer.name == "IP")
    fields = {f.name: f.human for f in ip_layer.fields}
    assert "src" in fields and "dst" in fields


def test_hexdump_format():
    lines = scapy_tree.hexdump_lines(bytes(range(20)))
    assert lines[0].startswith("00000000  ")
    assert len(lines) == 2  # 16 + 4 bytes
    # offset, hex, ascii present
    assert "  " in lines[0]
