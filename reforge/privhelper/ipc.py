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
