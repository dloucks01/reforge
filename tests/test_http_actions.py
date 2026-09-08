"""HTTP-toolkit rule actions applied to real packets (and non-HTTP no-ops)."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.attacks import http_actions as H
from reforge.core.packet import Packet
from reforge.rules.base import Verdict


def _pkt(payload: bytes, sport=80):
    return Packet.from_bytes(bytes(Ether() / IP() / TCP(sport=sport) / Raw(payload)))


def _resp(body: bytes, headers: str = "", ctype: str = "text/html"):
    return (f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n{headers}\r\n").encode() + body


def _apply(action, pkt):
    v = Verdict()
    action.apply(pkt, v)
    return v


def test_sslstrip_rewrites_https_links():
    p = _pkt(_resp(b'<a href="https://bank.example/login">go</a></body>'))
    v = _apply(H.SslStrip(), p)
    assert p.modified and b"http://bank.example" in bytes(p.scapy()[Raw].load)
    assert any("sslstrip" in n for n in v.notes)


def test_strip_accept_encoding_from_request():
    req = b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, deflate\r\n\r\n"
    p = _pkt(req)
    _apply(H.StripAcceptEncoding(), p)
    assert p.modified and b"Accept-Encoding" not in bytes(p.scapy()[Raw].load)


def test_inject_html_before_marker():
    p = _pkt(_resp(b"<html><body>hi</body></html>"))
    _apply(H.InjectHtml("<script>x()</script>"), p)
    out = bytes(p.scapy()[Raw].load)
    assert p.modified and b"<script>x()</script></body>" in out


def test_replace_body_swaps_content():
    p = _pkt(_resp(b"<html><body>original</body></html>"))
    _apply(H.ReplaceBody("<h1>owned</h1>", content_type="text/html"), p)
    assert p.modified and b"owned" in bytes(p.scapy()[Raw].load)


def test_strip_secure_cookie_flags():
    p = _pkt(_resp(b"ok", headers="Set-Cookie: sid=abc; Secure; HttpOnly\r\n"))
    _apply(H.StripSecureCookie(), p)
    out = bytes(p.scapy()[Raw].load)
    assert p.modified and b"Secure" not in out


def test_remove_security_headers():
    p = _pkt(_resp(b"ok", headers="Strict-Transport-Security: max-age=99999\r\n"))
    _apply(H.RemoveSecurityHeaders(), p)
    assert p.modified and b"Strict-Transport-Security" not in bytes(p.scapy()[Raw].load)


def test_non_http_and_no_raw_are_noops():
    garbage = _pkt(b"\x00\x01\x02 not http at all")
    _apply(H.SslStrip(), garbage)
    assert not garbage.modified
    bare = Packet.from_bytes(bytes(Ether() / IP() / TCP()))   # no Raw
    _apply(H.SslStrip(), bare)
    assert not bare.modified
