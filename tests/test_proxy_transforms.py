"""tcp_proxy transform builders + http_relay.apply_transforms (pure, no sockets)."""

from __future__ import annotations

from reforge.attacks import http, tcp_proxy
from reforge.attacks.http_relay import apply_transforms


def _resp(body=b"<html><body>hi</body></html>", headers=""):
    raw = (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
           f"Content-Length: {len(body)}\r\n{headers}\r\n").encode() + body
    return http.parse_http(raw)


def _req(headers="Accept-Encoding: gzip\r\n"):
    raw = (f"GET / HTTP/1.1\r\nHost: x\r\n{headers}\r\n").encode()
    return http.parse_http(raw)


def test_inject_only_on_server_side():
    fn = tcp_proxy.inject(b"<script>x</script>")
    msg = _resp()
    assert fn(msg, from_client=False) is True          # server->client injected
    assert b"<script>x</script>" in http.build_http(msg)
    assert fn(_resp(), from_client=True) in (False, None)  # not on client requests


def test_strip_accept_encoding_only_on_client_side():
    fn = tcp_proxy.strip_accept_encoding()
    req = _req()
    assert fn(req, from_client=True) is True
    assert http.build_http(req).count(b"Accept-Encoding") == 0
    assert fn(_req(), from_client=False) in (False, None)


def test_sslstrip_and_replace_body_and_cookie_and_headers():
    ss = tcp_proxy.sslstrip()
    m = http.parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\nhttps://x/ is secure")
    assert ss(m, from_client=False) is True

    rb = tcp_proxy.replace_body(b"OWNED", "text/plain")
    m2 = _resp()
    assert rb(m2, from_client=False) is True and b"OWNED" in http.build_http(m2)

    sc = tcp_proxy.strip_secure_cookie()
    m3 = _resp(headers="Set-Cookie: s=1; Secure; HttpOnly\r\n")
    assert sc(m3, from_client=False) is True

    rh = tcp_proxy.remove_security_headers()
    m4 = _resp(headers="Strict-Transport-Security: max-age=1\r\n")
    assert rh(m4, from_client=False) is True


def test_apply_transforms_changes_and_passthrough():
    raw = http.build_http(_resp())                     # correctly framed HTML response
    out = apply_transforms(raw, from_client=False, transforms=[tcp_proxy.inject(b"<i>Z</i>")])
    assert b"<i>Z</i>" in out and out != raw

    # non-HTTP bytes pass through unchanged
    assert apply_transforms(b"\x00\x01\x02 not http", False, [tcp_proxy.sslstrip()]) == \
        b"\x00\x01\x02 not http"

    # a transform that raises is swallowed; message unchanged
    def boom(msg, from_client):
        raise RuntimeError("bad transform")
    assert apply_transforms(raw, False, [boom]) == raw
