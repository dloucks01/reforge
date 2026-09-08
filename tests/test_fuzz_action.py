"""craft.fuzz: byte/bit mutators + the inline Fuzz rule action (both branches)."""

from __future__ import annotations

import random

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.core.packet import Packet
from reforge.craft.fuzz import Fuzz, bit_flip, byte_set, mutate
from reforge.rules.base import Verdict


def test_mutators_preserve_length_and_handle_empty():
    rng = random.Random(1)
    assert bit_flip(b"", rng) == b""
    assert byte_set(b"", rng) == b""
    data = b"A" * 32
    assert len(bit_flip(data, rng)) == 32
    assert len(byte_set(data, rng)) == 32


def test_mutate_is_deterministic_and_length_preserving():
    data = bytes(range(64))
    a = mutate(data, mutations=8, seed=7)
    b = mutate(data, mutations=8, seed=7)
    assert a == b and len(a) == len(data) and a != data


def test_fuzz_action_mutates_raw_payload():
    pkt = Packet.from_bytes(bytes(Ether() / IP() / TCP() / Raw(b"PAYLOAD-DATA-1234")))
    v = Verdict()
    Fuzz(mutations=6, seed=3).apply(pkt, v)
    assert pkt.modified is True
    assert any("fuzz" in n for n in v.notes)
    out = pkt.scapy()
    assert bytes(out[Raw].load) != b"PAYLOAD-DATA-1234"
    assert len(bytes(out[Raw].load)) == len(b"PAYLOAD-DATA-1234")   # length preserved


def test_fuzz_action_mutates_dissected_transport_payload():
    # UDP/DNS has no Raw layer -> the l4-payload branch fuzzes the DNS bytes
    pkt = Packet.from_bytes(bytes(Ether() / IP() / UDP(dport=53)
                                  / DNS(rd=1, qd=DNSQR(qname="a.example"))))
    assert not pkt.scapy().haslayer(Raw)
    v = Verdict()
    Fuzz(mutations=4, seed=1).apply(pkt, v)
    assert pkt.modified is True
    assert pkt.scapy().haslayer(Raw)                 # payload replaced with fuzzed bytes


def test_fuzz_action_no_payload_is_noop():
    pkt = Packet.from_bytes(bytes(Ether() / IP() / TCP()))    # no payload at all
    v = Verdict()
    Fuzz(mutations=2, seed=1).apply(pkt, v)
    assert pkt.modified is False and v.notes == []


def test_fuzz_fields_returns_a_packet():
    from reforge.craft.fuzz import fuzz_fields
    fuzzed = fuzz_fields(IP() / TCP())
    assert fuzzed.haslayer(TCP)
