"""TLS intercepting proxy (certificate-injection MITM).

Terminates the victim's TLS using a forged certificate minted by the DynamicCA
for the SNI it requested, decrypts, optionally transforms the plaintext (e.g.
the HTTP toolkit), then re-encrypts to the real upstream. This turns every inline
manipulation loose on HTTPS — provided the victim trusts the CA.

Peeks the ClientHello (MSG_PEEK) to learn the SNI before the handshake, so it can
present the right certificate and pick the upstream. For authorized testing only.
"""

from __future__ import annotations

import logging
import select
import socket
import ssl
import threading
from typing import Callable

from reforge.attacks.tls_ca import DynamicCA
from reforge.attacks.tls_sni import extract_sni

log = logging.getLogger("reforge.tls")


class TlsInterceptor:
    def __init__(self, ca: DynamicCA | None = None,
                 listen: tuple[str, int] = ("127.0.0.1", 0),
                 upstream_resolver: Callable[[str], tuple[str, int]] | None = None,
                 modify: Callable[[bytes, bool], bytes] | None = None,
                 http_transforms: list[Callable] | None = None,
                 verify_upstream: bool = False,
                 default_host: str = "localhost",
                 interceptor=None):
        self.ca = ca or DynamicCA()
        self.listen = listen
        self.resolver = upstream_resolver or (lambda sni: (sni, 443))
        self.modify = modify                      # raw per-chunk hook (optional)
        self.http_transforms = http_transforms    # message-framed HTTP toolkit
        self.interceptor = interceptor            # optional MessageInterceptor
        self.verify_upstream = verify_upstream
        self.default_host = default_host
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.port = None
        self.intercepted = 0

    def start(self) -> int:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(self.listen)
        self._srv.listen(50)
        self.port = self._srv.getsockname()[1]
        self._running.set()
        self._thread = threading.Thread(target=self._accept, name="reforge-tls", daemon=True)
        self._thread.start()
        log.info("TLS interceptor on %s:%d", self.listen[0], self.port)
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
        try:
            client.settimeout(8)
            hello = client.recv(4096, socket.MSG_PEEK)
            sni = extract_sni(hello) or self.default_host

            server_ctx = self.ca.context_for(sni)
            tls_client = server_ctx.wrap_socket(client, server_side=True)

            host, port = self.resolver(sni)
            up = socket.create_connection((host, port), timeout=8)
            cctx = ssl.create_default_context()
            if not self.verify_upstream:
                cctx.check_hostname = False
                cctx.verify_mode = ssl.CERT_NONE
            tls_up = cctx.wrap_socket(up, server_hostname=sni)

            self.intercepted += 1
            if self.http_transforms is not None or self.interceptor is not None:
                # Full HTTP framing + toolkit transforms (and optional interactive
                # message intercept) on the decrypted stream — same path as the
                # plaintext TCP proxy, so HTTPS gets large-body rewrite + hold/edit.
                from reforge.attacks.http_relay import run_http_relay

                run_http_relay(tls_client, tls_up, self.http_transforms or [], self.interceptor)
            else:
                self._relay(tls_client, tls_up)   # raw per-chunk modify hook
        except Exception:
            log.debug("TLS intercept error", exc_info=True)
            try:
                client.close()
            except Exception:
                pass

    def _relay(self, client, upstream) -> None:
        socks = [client, upstream]
        try:
            while True:
                r, _, _ = select.select(socks, [], [], 5.0)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    from_client = s is client
                    if self.modify:
                        data = self.modify(data, from_client)
                    (upstream if from_client else client).sendall(data)
        finally:
            for s in socks:
                try:
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
