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

log = logging.getLogger("reforge.tcpproxy")

SO_ORIGINAL_DST = 80


def so_original_dst(sock: socket.socket) -> tuple[str, int] | None:  # pragma: no cover
    """Recover the pre-REDIRECT destination of a transparently-redirected conn."""
    try:
        data = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        port = struct.unpack("!H", data[2:4])[0]
        host = socket.inet_ntoa(data[4:8])
        return host, port
    except Exception:
        return None


class TcpProxy:
    def __init__(self, upstream_resolver: Callable[[socket.socket], tuple[str, int]],
                 http_transforms: list[Callable] | None = None,
                 listen: tuple[str, int] = ("127.0.0.1", 0),
                 interceptor=None):
        self.resolver = upstream_resolver
        self.transforms = http_transforms or []
        self.interceptor = interceptor      # optional MessageInterceptor (hold/edit)
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
        from reforge.attacks.http_relay import run_http_relay

        upstream = None
        try:
            host, port = self.resolver(client)
            upstream = socket.create_connection((host, port), timeout=10)
            self.flows += 1
            run_http_relay(client, upstream, self.transforms, self.interceptor)
        except Exception:
            log.debug("proxy flow error", exc_info=True)
        finally:
            for s in (client, upstream):
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

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
