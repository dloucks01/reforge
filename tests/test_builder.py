"""craft.builder: layer/field coercion, spec<->bytes round-trip, layer_fields."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.craft import builder as B


def test_coerce_load_and_numeric():
    assert B._coerce(Raw, "load", "0xdead") == b"\xde\xad"
    assert B._coerce(Raw, "load", "hello") == b"hello"
    assert B._coerce(Raw, "load", b"raw") == b"raw"
    assert B._coerce(TCP, "dport", "80") == 80          # numeric string -> int
    assert B._coerce(TCP, "dport", "not-a-number") == "not-a-number"


def test_spec_to_bytes_and_back():
    spec = {"layers": [
        {"layer": "Ether"},
        {"layer": "IP", "fields": {"dst": "10.0.0.9"}},
        {"layer": "TCP", "fields": {"dport": "80"}},
        {"layer": "Raw", "fields": {"load": "0xdeadbeef"}},
    ]}
    data = B.spec_to_bytes(spec)
    pkt = Ether(data)
    assert pkt[IP].dst == "10.0.0.9"
    assert pkt[TCP].dport == 80
    assert bytes(pkt[Raw].load) == b"\xde\xad\xbe\xef"

    back = B.bytes_to_spec(data)
    assert [ly["layer"] for ly in back["layers"]][:3] == ["Ether", "IP", "TCP"]


def test_empty_spec_yields_ether():
    data = B.spec_to_bytes({"layers": []})
    assert Ether(data).name == "Ethernet"


def test_layer_fields_lists_named_fields():
    fields = B.layer_fields("IP")
    names = {n for n, _v in fields}
    assert {"src", "dst", "ttl"} <= names
