"""Local IPC between the unprivileged GUI and the privileged helper.

A newline-delimited JSON protocol over a Unix domain socket. No network exposure
(airgapped, local-only). The GUI never runs as root; only the small helper holds
CAP_NET_RAW / CAP_NET_ADMIN.
"""

from __future__ import annotations

import json
import socket
from dataclasses import dataclass


@dataclass
class Request:
    op: str                 # e.g. "prepare_iface", "start_pipeline", "revert", "doctor"
    args: dict


@dataclass
class Response:
    ok: bool
    data: dict
    error: str = ""


def encode(obj: dict) -> bytes:
    return (json.dumps(obj) + "\n").encode()


def decode_line(line: bytes) -> dict:
    return json.loads(line.decode())


def send_request(sock_path: str, req: Request, timeout: float = 5.0) -> Response:
    """Connect, send one request, read one response."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(sock_path)
        s.sendall(encode({"op": req.op, "args": req.args}))
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    payload = decode_line(buf) if buf else {"ok": False, "error": "no response"}
    return Response(ok=payload.get("ok", False),
                    data=payload.get("data", {}),
                    error=payload.get("error", ""))


class HelperClient:
    """Typed client for the privileged helper, over the local Unix socket.

    Callers (GUI/CLI) use this so privileged config runs in the root helper rather
    than in the caller's process. `available()` reports whether a helper socket is
    present, so a caller can fall back to applying commands directly when it is
    itself privileged and no helper is running.
    """

    def __init__(self, sock_path: str | None = None, timeout: float = 5.0):
        from reforge.constants import HELPER_SOCKET
        self.sock_path = str(sock_path or HELPER_SOCKET)
        self.timeout = timeout

    def available(self) -> bool:
        import os
        return os.path.exists(self.sock_path)

    def _call(self, op: str, **args) -> Response:
        return send_request(self.sock_path, Request(op=op, args=args), self.timeout)

    def ping(self) -> Response:
        return self._call("ping")

    def prepare_iface(self, iface: str, apply: bool = True) -> Response:
        return self._call("prepare_iface", iface=iface, apply=apply)

    def prepare_bridge(self, if_a: str, if_b: str, apply: bool = True) -> Response:
        return self._call("prepare_bridge", if_a=if_a, if_b=if_b, apply=apply)

    def suppress_host_stack(self, iface: str, apply: bool = True) -> Response:
        return self._call("suppress_host_stack", iface=iface, apply=apply)

    def fail_open(self, if_a: str, if_b: str, apply: bool = True) -> Response:
        return self._call("fail_open", if_a=if_a, if_b=if_b, apply=apply)

    def fail_closed(self, if_a: str, if_b: str, apply: bool = True) -> Response:
        return self._call("fail_closed", if_a=if_a, if_b=if_b, apply=apply)

    def queue_install(self, queue_num: int = 1, victims: list[str] | None = None,
                      apply: bool = True) -> Response:
        return self._call("queue_install", queue_num=queue_num, victims=victims, apply=apply)

    def queue_remove(self, apply: bool = True) -> Response:
        return self._call("queue_remove", apply=apply)

    def revert(self) -> Response:
        return self._call("revert")
