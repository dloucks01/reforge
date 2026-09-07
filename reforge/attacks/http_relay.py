"""Shared HTTP-framing relay.

Pumps bytes between two connected sockets, framing complete HTTP messages per
direction (HttpFramer) and applying the toolkit transforms before forwarding, so
full/large bodies are rewritten correctly. Non-HTTP flows pass through raw.

Used by both the plaintext TCP proxy and the TLS interceptor (after decryption),
so HTTPS gets the same full-body rewriting as HTTP. For authorized testing only.
"""

from __future__ import annotations

import socket
import threading
from typing import Callable

from reforge.attacks import http
from reforge.core.httpframer import HttpFramer

_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"HTTP/")


def looks_http(data: bytes) -> bool:
    return data[:8].startswith(_METHODS)


def apply_transforms(raw_msg: bytes, from_client: bool, transforms: list[Callable]) -> bytes:
    msg = http.parse_http(raw_msg)
    if msg is None:
        return raw_msg
    changed = False
    for fn in transforms:
        try:
            changed = fn(msg, from_client) or changed
        except Exception:
            pass
    return http.build_http(msg) if changed else raw_msg


def _pump(src, dst, from_client: bool, transforms: list[Callable]) -> None:
    framer = HttpFramer()
    mode: str | None = None
    try:
        while True:
            data = src.recv(65536)
            if not data:
                rest = framer.flush()
                if rest:
                    dst.sendall(rest)
                break
            if mode is None:
                mode = "http" if looks_http(data) else "raw"
            if mode == "raw":
                dst.sendall(data)
                continue
            for msg in framer.feed(data):
                dst.sendall(apply_transforms(msg, from_client, transforms))
    except Exception:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def run_http_relay(client, upstream, transforms: list[Callable]) -> None:
    """Relay both directions with HTTP framing + transforms; blocks until done."""
    t1 = threading.Thread(target=_pump, args=(client, upstream, True, transforms), daemon=True)
    t2 = threading.Thread(target=_pump, args=(upstream, client, False, transforms), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
