"""Intercept/search filter expression parser."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.core.packet import Packet
from reforge.rules.filter import FilterError, parse_filter


def _pkt(scapy_pkt) -> Packet:
    return Packet.from_bytes(bytes(scapy_pkt), link="ether")


HTTP = _pkt(Ether() / IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=5, dport=80) / Raw(b"POST /login HTTP/1.1"))
SSH = _pkt(Ether() / IP(src="192.168.1.4") / TCP(sport=6, dport=22) / Raw(b"SSH-2.0"))
DNS = _pkt(Ether() / IP(src="10.0.0.9") / UDP(dport=53))


def test_field_eq_and_layer():
    assert parse_filter("TCP.dport == 80").matches(HTTP)
    assert not parse_filter("TCP.dport == 80").matches(SSH)
    assert parse_filter("UDP").matches(DNS)
    assert not parse_filter("UDP").matches(HTTP)


def test_and_or_not_precedence():
    m = parse_filter("IP.src cidr 10.0.0.0/24 and TCP.dport == 80")
    assert m.matches(HTTP) and not m.matches(SSH)
    m2 = parse_filter('Raw.load contains "login" or Raw.load contains "SSH"')
    assert m2.matches(HTTP) and m2.matches(SSH)
    m3 = parse_filter("not TCP.dport == 22")
    assert m3.matches(HTTP) and not m3.matches(SSH)


def test_in_list_and_cidr_and_contains():
    assert parse_filter("TCP.dport in [22, 80, 443]").matches(HTTP)
    assert parse_filter("TCP.dport in [22, 80, 443]").matches(SSH)
    assert not parse_filter("TCP.dport in [443, 8080]").matches(HTTP)
    assert parse_filter("IP.src cidr 10.0.0.0/8").matches(HTTP)
    assert not parse_filter("IP.src cidr 172.16.0.0/12").matches(HTTP)
    assert parse_filter('Raw.load contains "/login"').matches(HTTP)


def test_hex_number_and_parens():
    assert parse_filter("TCP.dport == 0x50").matches(HTTP)          # 0x50 == 80
    m = parse_filter("(TCP.dport == 22 or TCP.dport == 80) and IP.src cidr 10.0.0.0/24")
    assert m.matches(HTTP) and not m.matches(SSH)


@pytest.mark.parametrize("bad", ["", "TCP.", "and 80", "TCP.dport foo 80",
                                 "(TCP.dport == 80", "TCP.dport in [80,"])
def test_malformed_raises(bad):
    with pytest.raises(FilterError):
        parse_filter(bad)


def test_match_error_never_raises_through_engine():
    # a field that doesn't exist on the packet just doesn't match (never raises)
    assert not parse_filter("ICMP.type == 8").matches(HTTP)
