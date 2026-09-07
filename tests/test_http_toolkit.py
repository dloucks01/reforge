"""HTTP attack toolkit: parsing, transforms, and rule-action integration."""

from __future__ import annotations

import gzip

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.attacks import http
from reforge.core.apply import apply_engine
from reforge.rules import matchers as M
from reforge.rules import spec as S
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _resp(body: bytes, headers: str = "", ctype: str = "text/html"):
    head = (f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\n{headers}\r\n").encode()
    return head + body


# ---- parse / build ---------------------------------------------------------
def test_parse_and_rebuild_roundtrip():
    msg = http.parse_http(_resp(b"<html><body>hi</body></html>"))
    assert msg.is_response and msg.get("Content-Type").startswith("text/html")
    out = http.build_http(msg)
    assert out.endswith(b"<html><body>hi</body></html>")
    assert b"Content-Length: 28" in out


def test_parse_gzip_body_is_decompressed():
    body = gzip.compress(b"<html><body>secret</body></html>")
    raw = _resp(body, headers="Content-Encoding: gzip\r\n")
    msg = http.parse_http(raw)
    assert b"secret" in msg.body                       # transparently decoded
    assert msg.get("Content-Encoding") is None         # encoding stripped


def test_parse_chunked_body():
    body = b"5\r\nHELLO\r\n5\r\nWORLD\r\n0\r\n\r\n"
    raw = _resp(body, headers="Transfer-Encoding: chunked\r\n")
    msg = http.parse_http(raw)
    assert msg.body == b"HELLOWORLD"


# ---- transforms ------------------------------------------------------------
def test_sslstrip_downgrades_and_strips_hsts():
    raw = _resp(b'<a href="https://bank.example/login">go</a>',
                headers="Strict-Transport-Security: max-age=31536000\r\n"
                        "Location: https://bank.example/\r\n")
    msg = http.parse_http(raw)
    assert http.sslstrip(msg)
    assert b"http://bank.example/login" in msg.body
    assert msg.get("Strict-Transport-Security") is None
    assert msg.get("Location") == "http://bank.example/"


def test_inject_html_before_body_close():
    msg = http.parse_http(_resp(b"<html><body>hi</body></html>"))
    assert http.inject_html(msg, b"<script>x()</script>")
    assert msg.body == b"<html><body>hi<script>x()</script></body></html>"


def test_replace_body_file_swap():
    msg = http.parse_http(_resp(b"MZ...real.exe", ctype="application/octet-stream"))
    assert http.replace_body(msg, b"PAYLOAD", content_type="application/octet-stream")
    assert msg.body == b"PAYLOAD"


def test_strip_secure_cookie():
    raw = _resp(b"ok", headers="Set-Cookie: SID=abc; Path=/; Secure; HttpOnly; SameSite=Strict\r\n")
    msg = http.parse_http(raw)
    assert http.strip_secure_cookie(msg)
    sc = msg.get("Set-Cookie").lower()
    assert "secure" not in sc and "httponly" not in sc and "samesite" not in sc


def test_strip_accept_encoding_on_request():
    req = (b"GET / HTTP/1.1\r\nHost: t\r\nAccept-Encoding: gzip, deflate\r\n\r\n")
    msg = http.parse_http(req)
    assert http.strip_accept_encoding(msg)
    assert msg.get("Accept-Encoding") is None


# ---- rule-action integration ----------------------------------------------
def _pkt(payload: bytes):
    return bytes(Ether() / IP(src="1.1.1.1", dst="10.0.0.5") / TCP(sport=80, dport=44000) / payload)


def test_http_inject_action_via_engine():
    action = S.build_action({"type": "http_inject", "snippet": "<script>evil()</script>"})
    engine = RuleEngine([Rule("inj", M.AllMatch(), [action])])
    res = apply_engine(engine, _pkt(_resp(b"<html><body>page</body></html>")))
    assert res.modified
    from scapy.packet import Raw
    out_body = bytes(Ether(res.out)[Raw].load)
    assert b"<script>evil()</script></body>" in out_body


def test_http_sslstrip_action_via_engine():
    action = S.build_action({"type": "http_sslstrip"})
    engine = RuleEngine([Rule("ss", M.AllMatch(), [action])])
    raw = _resp(b'link: https://x.example/', headers="Strict-Transport-Security: max-age=1\r\n")
    res = apply_engine(engine, _pkt(raw))
    assert res.modified
    from scapy.packet import Raw
    out = bytes(Ether(res.out)[Raw].load)
    assert b"http://x.example/" in out and b"Strict-Transport-Security" not in out
