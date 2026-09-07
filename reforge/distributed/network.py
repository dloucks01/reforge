"""Network transport for sensors → collector (local/airgapped TCP, JSON lines).

SECURITY: this transport is unauthenticated and unencrypted. Bind the collector
to loopback (the default) or a trusted management segment only; for sensors on a
separate host, tunnel the connection (SSH/WireGuard). An attacker who can reach
an exposed collector port can inject false observations or read reported
credentials in transit. Do not bind to an untrusted network without a tunnel.
"""

from __future__ import annotations

import socket
import threading

from reforge.distributed.collector import Collector


class CollectorServer:
    def __init__(self, collector: Collector, bind: tuple[str, int] = ("127.0.0.1", 0)):
        self.collector = collector
        self.bind = bind
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.port = None

    def start(self) -> int:
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(self.bind)
        self._srv.listen(50)
        self.port = self._srv.getsockname()[1]
        self._running.set()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()
        return self.port

    def _accept(self) -> None:
        self._srv.settimeout(0.3)
        while self._running.is_set():
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        buf = b""
        with conn:
            conn.settimeout(2.0)
            while self._running.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, _, buf = buf.partition(b"\n")
                    if line.strip():
                        try:
                            self.collector.ingest_line(line)
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
            self._thread.join(timeout=1.0)


class NetworkSink:
    """Callable(Message) that streams messages to a CollectorServer."""

    def __init__(self, host: str, port: int):
        self.sock = socket.create_connection((host, port), timeout=5)

    def __call__(self, msg) -> None:
        try:
            self.sock.sendall(msg.encode())
        except OSError:
            pass

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
