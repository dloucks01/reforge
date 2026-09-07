"""TCP proxy mode — active large-body HTTP rewriting done correctly.

Terminates a matched TCP flow locally, reassembles each direction into complete
HTTP messages (via HttpFramer), applies the HTTP toolkit transforms, and
re-originates a correctly-framed stream to the real upstream. This is the clean
way to rewrite bodies that span many segments (the transparent per-segment path
can't) — the same approach mature MITM proxies use.

Original destination comes from a resolver: SO_ORIGINAL_DST for iptables REDIRECT,
or a fixed target (tests / static redirection). Non-HTTP flows pass through raw.

For authorized testing only. See docs/REASSEMBLY-PLAN.md (R2).
"""

from __future__ import annotations

import logging
import socket
import struct
import threading
from typing import Callable

from reforge.attacks import http
from reforge.core.httpframer import HttpFramer

log = logging.getLogger("reforge.tcpproxy")

SO_ORIGINAL_DST = 80
_METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH", b"HTTP/")


def so_original_dst(sock: socket.socket) -> tuple[str, int] | None:  # pragma: no cover
    """Recover the pre-REDIRECT destination of a transparently-redirected conn."""
    try:
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", data[2:4])[0]
        host = socket.inet_ntoa(data[4:8])
        return host, port
    except Exception:
        return None


def _looks_http(data: bytes) -> bool:
    return data[:8].startswith(_METHODS)


class TcpProxy:
    def __init__(self, upstream_resolver: Callable[[socket.socket], tuple[str, int]],
                 http_transforms: list[Callable] | None = None,
                 listen: tuple[str, int] = ("127.0.0.1", 0)):
        self.resolver = upstream_resolver
        self.transforms = http_transforms or []
        self.listen = listen
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.port = None
        self.flows = 0

    def start(self) -> int:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(self.listen)
        self._srv.listen(50)
        self.port = self._srv.getsockname()[1]
        self._running.set()
        self._thread = threading.Thread(target=self._accept, name="reforge-tcpproxy", daemon=True)
        self._thread.start()
        log.info("TCP proxy on %s:%d", self.listen[0], self.port)
        return self.port

    def _accept(self) -> None:
        self._srv.settimeout(0.5)
        while self._running.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            host, port = self.resolver(client)
            upstream = socket.create_connection((host, port), timeout=10)
            self.flows += 1
            t1 = threading.Thread(target=self._pump, args=(client, upstream, True), daemon=True)
            t2 = threading.Thread(target=self._pump, args=(upstream, client, False), daemon=True)
            t1.start(); t2.start()
            t1.join(); t2.join()
        except Exception:
            log.debug("proxy flow error", exc_info=True)
        finally:
            for s in (client, upstream):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    def _pump(self, src: socket.socket, dst: socket.socket, from_client: bool) -> None:
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
                    mode = "http" if _looks_http(data) else "raw"
                if mode == "raw":
                    dst.sendall(data)
                    continue
                for msg in framer.feed(data):
                    dst.sendall(self._apply(msg, from_client))
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _apply(self, raw_msg: bytes, from_client: bool) -> bytes:
        msg = http.parse_http(raw_msg)
        if msg is None:
            return raw_msg
        changed = False
        for fn in self.transforms:
            try:
                changed = fn(msg, from_client) or changed
            except Exception:
                log.debug("transform error", exc_info=True)
        return http.build_http(msg) if changed else raw_msg

    def stop(self) -> None:
        self._running.clear()
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass
        if self._thread:
            self._thread.join(timeout=2.0)


# ---- transform builders (adapt the http toolkit to (msg, from_client)) ------
def inject(snippet: bytes, marker: bytes = b"</body>"):
    return lambda msg, from_client: (not from_client) and http.inject_html(msg, snippet, marker)


def sslstrip():
    return lambda msg, from_client: http.sslstrip(msg)


def strip_accept_encoding():
    return lambda msg, from_client: from_client and http.strip_accept_encoding(msg)


def replace_body(new_body: bytes, content_type: str | None = None):
    return lambda msg, from_client: (not from_client) and http.replace_body(msg, new_body, content_type)


def strip_secure_cookie():
    return lambda msg, from_client: http.strip_secure_cookie(msg)


def remove_security_headers():
    return lambda msg, from_client: http.remove_security_headers(msg)
