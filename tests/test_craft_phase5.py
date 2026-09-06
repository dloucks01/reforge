"""Phase 5: packet crafting (build, coerce, checksum, capture->spec round-trip)."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.craft import builder


def test_available_layers_and_fields():
    layers = builder.available_layers()
    assert {"Ether", "IP", "TCP", "UDP", "Raw"} <= set(layers)
    names = [n for n, _ in builder.layer_fields("TCP")]
    assert {"sport", "dport", "flags"} <= set(names)


def test_build_packet_from_spec():
    spec = {"layers": [
        {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff"}},
        {"layer": "IP", "fields": {"dst": "10.0.0.9"}},
        {"layer": "UDP", "fields": {"dport": 53}},
        {"layer": "Raw", "fields": {"load": "hello"}},
    ]}
    data = builder.spec_to_bytes(spec)
    pkt = Ether(data)
    assert pkt.dst == "ff:ff:ff:ff:ff:ff"
    assert pkt[IP].dst == "10.0.0.9"
    assert pkt[UDP].dport == 53
    assert bytes(pkt[UDP].payload) == b"hello"


def test_numeric_field_coercion_from_string():
    # values arrive from the GUI as strings; must coerce to int
    spec = {"layers": [{"layer": "IP"}, {"layer": "TCP", "fields": {"dport": "443"}}]}
    pkt = IP(builder.spec_to_bytes(spec))
    assert pkt[TCP].dport == 443


def test_checksum_computed_on_build():
    spec = {"layers": [{"layer": "IP", "fields": {"dst": "1.2.3.4"}},
                       {"layer": "TCP", "fields": {"dport": 80}}]}
    data = builder.spec_to_bytes(spec)
    pkt = IP(data)
    stored = pkt[IP].chksum
    del pkt[IP].chksum
    assert IP(bytes(pkt))[IP].chksum == stored  # checksum was valid


def test_load_hex_payload():
    spec = {"layers": [{"layer": "Raw", "fields": {"load": "0xdeadbeef"}}]}
    assert builder.spec_to_bytes(spec) == b"\xde\xad\xbe\xef"


def test_packet_to_spec_round_trip():
    original = bytes(Ether(dst="aa:bb:cc:dd:ee:ff") / IP(dst="10.0.0.1")
                     / TCP(dport=8080) / b"data")
    spec = builder.bytes_to_spec(original)
    names = [ld["layer"] for ld in spec["layers"]]
    assert names[:3] == ["Ether", "IP", "TCP"]
    rebuilt = Ether(builder.spec_to_bytes(spec))
    assert rebuilt[IP].dst == "10.0.0.1"
    assert rebuilt[TCP].dport == 8080
    assert b"data" in bytes(rebuilt[TCP].payload)


def test_spec_drops_auto_fields():
    # captured packet has a concrete checksum, but the spec must not pin it
    original = bytes(IP(dst="10.0.0.1") / TCP(dport=80))
    spec = builder.bytes_to_spec(original, link="ip")
    ip_layer = next(ld for ld in spec["layers"] if ld["layer"] == "IP")
    assert "chksum" not in ip_layer["fields"]
    assert "len" not in ip_layer["fields"]
