"""Credential extraction edge cases: SNMP, SMTP AUTH PLAIN, HTTP cookies."""

from __future__ import annotations

import base64

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.attacks.creds import CredentialExtractor, _b64, _is_b64


def _extract(pkt):
    return CredentialExtractor().extract(pkt)


def test_snmp_community_string():
    from scapy.layers.snmp import SNMP
    built = Ether() / IP() / UDP(sport=40000, dport=161) / SNMP(community="s3cr3tcomm")
    pkt = Ether(bytes(built))                       # as captured off the wire
    creds = _extract(pkt)
    assert any(c.kind == "snmp" and c.secret == "s3cr3tcomm" for c in creds)


def test_smtp_auth_plain():
    token = base64.b64encode(b"\x00admin\x00s3cr3t").decode()
    payload = f"AUTH PLAIN {token}\r\n".encode()
    pkt = Ether() / IP() / TCP(sport=50000, dport=25) / Raw(payload)
    creds = _extract(pkt)
    assert any(c.username == "admin" and c.secret == "s3cr3t" for c in creds)


def test_http_cookie_captured():
    req = (b"GET / HTTP/1.1\r\nHost: x\r\nCookie: session=abc123def\r\n\r\n")
    pkt = Ether() / IP() / TCP(sport=50001, dport=80) / Raw(req)
    creds = _extract(pkt)
    assert any("abc123def" in (c.secret or "") for c in creds)


def test_b64_helpers():
    assert _is_b64("YWRtaW4=") is True
    assert _is_b64("not base64!") is False
    assert _is_b64("abc") is False                 # length not multiple of 4
    assert _b64(base64.b64encode(b"hi").decode()) == "hi"
    assert _b64("!!!not!!!") == ""                 # bad input -> empty
