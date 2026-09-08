"""Regression locks from the silent-drift sweep: collector scan-ingest,
custom-proto field types, entropy + fingerprint edges."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether


# ---- collector: scan-kind ingest merges into hosts ------------------------
def test_collector_scan_ingest_becomes_host():
    from reforge.distributed.collector import Collector
    from reforge.distributed.protocol import Message

    col = Collector()
    col.ingest(Message("s1", "scan", {"ip": "10.0.0.9", "open": [22, 80, 443]}))
    rep = col.report()
    host = next(h for h in rep.hosts if h["ip"] == "10.0.0.9")
    assert set(host["services"].keys()) >= {22, 80, 443}


# ---- custom_proto: all field types + bind by sport + unknown type ---------
def test_custom_proto_field_types_roundtrip():
    from reforge.craft.custom_proto import define_protocol

    define_protocol({"name": "MixedProto", "fields": [
        {"name": "op", "type": "u8"},
        {"name": "big", "type": "u32"},
        {"name": "le", "type": "u16le"},
        {"name": "sig", "type": "i8"},
        {"name": "tok", "type": "bytes", "size": 4},
        {"name": "tail", "type": "rest"},
    ], "bind": {"over": "UDP", "sport": 9300}})

    body = b"\x07" + b"\x00\x00\x00\x2a" + b"\x01\x00" + b"\xff" + b"ABCD" + b"trailing"
    raw = bytes(Ether() / IP() / UDP(sport=9300, dport=40000) / body)
    pkt = Ether(raw)
    assert pkt.haslayer("MixedProto")
    layer = pkt["MixedProto"]
    assert layer.op == 7 and layer.big == 0x2A and layer.le == 1
    assert layer.tok == b"ABCD" and bytes(layer.tail) == b"trailing"


def test_custom_proto_unknown_field_type_raises():
    from reforge.craft.custom_proto import define_protocol
    with pytest.raises(ValueError, match="unknown field type"):
        define_protocol({"name": "BadProto", "fields": [{"name": "x", "type": "float128"}]})


# ---- covert entropy edges -------------------------------------------------
def test_entropy_edges():
    from reforge.covert.detect import entropy
    assert entropy(b"") == 0.0
    assert entropy(b"AAAA") == 0.0                 # single symbol -> zero entropy
    assert entropy(bytes(range(256))) > 7.9        # uniform bytes -> ~8 bits


# ---- fingerprint edges ----------------------------------------------------
def test_fingerprint_unknown_ttl_bucket():
    from reforge.recon.fingerprint import os_from_syn
    # a very high TTL doesn't match the common initial-TTL buckets
    g = os_from_syn(IP(ttl=200) / TCP(flags="S", window=1000))
    assert g is None or g.initial_ttl in (255, 256) or g.confidence == "low"


def test_fingerprint_non_syn_is_none():
    from reforge.recon.fingerprint import os_from_syn
    assert os_from_syn(IP(ttl=64) / TCP(flags="A")) is None    # not a SYN
