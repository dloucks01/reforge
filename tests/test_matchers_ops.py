"""FieldMatch operators: eq/ne/num/in/contains/cidr + graceful failure paths."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.core.packet import Packet
from reforge.rules import matchers as M


def _pkt(scapy_pkt) -> Packet:
    return Packet.from_bytes(bytes(scapy_pkt))


def test_all_and_layer():
    p = _pkt(Ether() / IP() / TCP())
    assert M.AllMatch().matches(p)
    assert M.LayerMatch("TCP").matches(p)
    assert not M.LayerMatch("UDP").matches(p)


def test_eq_ne_numeric():
    p = _pkt(Ether() / IP() / TCP(dport=80))
    assert M.FieldMatch("TCP", "dport", "eq", 80).matches(p)
    assert not M.FieldMatch("TCP", "dport", "eq", 81).matches(p)
    assert M.FieldMatch("TCP", "dport", "ne", 81).matches(p)


def test_num_comparisons():
    p = _pkt(Ether() / IP() / TCP(dport=100))
    assert M.FieldMatch("TCP", "dport", "gt", 50).matches(p)
    assert M.FieldMatch("TCP", "dport", "ge", 100).matches(p)
    assert M.FieldMatch("TCP", "dport", "lt", 200).matches(p)
    assert M.FieldMatch("TCP", "dport", "le", 100).matches(p)
    assert not M.FieldMatch("TCP", "dport", "gt", 100).matches(p)


def test_in_operator():
    p = _pkt(Ether() / IP() / UDP(dport=53))
    assert M.FieldMatch("UDP", "dport", "in", [53, 5353]).matches(p)
    assert not M.FieldMatch("UDP", "dport", "in", [80, 443]).matches(p)
    # scalar value is treated as a one-element set
    assert M.FieldMatch("UDP", "dport", "in", 53).matches(p)


def test_contains_operator():
    p = _pkt(Ether() / IP(dst="10.20.30.40") / TCP())
    assert M.FieldMatch("IP", "dst", "contains", "20.30").matches(p)
    assert not M.FieldMatch("IP", "dst", "contains", "99").matches(p)


def test_cidr_operator():
    p = _pkt(Ether() / IP(dst="10.0.0.55") / TCP())
    assert M.FieldMatch("IP", "dst", "cidr", "10.0.0.0/24").matches(p)
    assert not M.FieldMatch("IP", "dst", "cidr", "192.168.0.0/16").matches(p)


def test_missing_layer_or_field_is_false():
    p = _pkt(Ether() / IP() / TCP())
    assert not M.FieldMatch("UDP", "dport", "eq", 53).matches(p)   # no UDP layer
    assert not M.FieldMatch("TCP", "nope", "eq", 1).matches(p)      # no such field


def test_unknown_op_is_false():
    p = _pkt(Ether() / IP() / TCP(dport=80))
    assert not M.FieldMatch("TCP", "dport", "weird", 80).matches(p)


def test_boolean_combinators():
    p = _pkt(Ether() / IP() / TCP(dport=80))
    tcp80 = M.FieldMatch("TCP", "dport", "eq", 80)
    udp = M.LayerMatch("UDP")
    assert M.AndMatch([M.LayerMatch("IP"), tcp80]).matches(p)
    assert M.OrMatch([udp, tcp80]).matches(p)
    assert not M.OrMatch([udp, M.FieldMatch("TCP", "dport", "eq", 22)]).matches(p)
    assert M.NotMatch(udp).matches(p)
    assert not M.NotMatch(tcp80).matches(p)
