"""HTTP message framer over a reassembled byte stream.

Buffers bytes from one direction of a connection and emits complete HTTP
messages (request or response), honoring Content-Length and chunked
Transfer-Encoding, so downstream transforms/harvesters see whole messages even
when they span many TCP segments (and multiple messages on a keep-alive stream).
"""

from __future__ import annotations

import re

_HEADER_END = b"\r\n\r\n"


def _header_value(header_block: bytes, name: str) -> str | None:
    pat = re.compile((r"(?im)^" + re.escape(name) + r":\s*(.+?)\s*$").encode())
    m = pat.search(header_block)
    return m.group(1).decode("latin-1", "replace") if m else None


def _chunked_end(buf: bytes, start: int) -> int | None:
    """Return the index just past the terminating 0-length chunk, or None."""
    i = start
    n = len(buf)
    while i < n:
        nl = buf.find(b"\r\n", i)
        if nl == -1:
            return None
        try:
            size = int(buf[i:nl].split(b";")[0], 16)
        except ValueError:
            return None
        data_start = nl + 2
        if size == 0:
            end = buf.find(b"\r\n", data_start)   # trailer terminator
            return end + 2 if end != -1 else None
        i = data_start + size + 2                  # skip data + CRLF
    return None


class HttpFramer:
    def __init__(self):
        self.buf = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        """Add bytes; return any complete HTTP messages now available."""
        self.buf += data
        out: list[bytes] = []
        while True:
            msg = self._extract()
            if msg is None:
                break
            out.append(msg)
        return out

    def _extract(self) -> bytes | None:
        i = self.buf.find(_HEADER_END)
        if i == -1:
            return None
        header_block = bytes(self.buf[:i])
        body_start = i + 4
        is_response = header_block[:5] == b"HTTP/"

        te = (_header_value(header_block, "Transfer-Encoding") or "").lower()
        cl = _header_value(header_block, "Content-Length")

        if "chunked" in te:
            end = _chunked_end(bytes(self.buf), body_start)
            if end is None:
                return None
            msg_end = end
        elif cl is not None:
            try:
                need = body_start + int(cl)
            except ValueError:
                need = body_start
            if len(self.buf) < need:
                return None
            msg_end = need
        else:
            # No framing info: requests and bodiless responses end at the header
            # block. (Response bodies delimited only by connection close need the
            # FIN — flushed by flush() on teardown.)
            msg_end = body_start

        msg = bytes(self.buf[:msg_end])
        del self.buf[:msg_end]
        return msg

    def flush(self) -> bytes:
        """Return whatever remains (e.g. on connection close)."""
        rest = bytes(self.buf)
        self.buf.clear()
        return rest
