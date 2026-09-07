"""Privileged helper process (skeleton).

Runs with elevated privileges (CAP_NET_RAW / CAP_NET_ADMIN), listens on a local
Unix socket, and performs the operations the unprivileged GUI is not allowed to:
interface prep, pipeline start/stop, teardown/revert. Phase 0 implements the
loop shape and a couple of safe ops; capture wiring lands in later phases.

Run:  sudo python -m reforge.privhelper.helper
"""

from __future__ import annotations

import logging
import os
import socket

from reforge.constants import HELPER_SOCKET, ensure_dirs
from reforge.logging_setup import setup_logging
from reforge.privhelper.ipc import decode_line, encode
from reforge.privhelper.netconfig import RevertJournal, prepare_capture_iface, suppress_host_stack

log = logging.getLogger("reforge.helper")


class Helper:
    def __init__(self):
        self.journal = RevertJournal()

    def handle(self, req: dict) -> dict:
        op = req.get("op")
        args = req.get("args", {})
        try:
            if op == "ping":
                return {"ok": True, "data": {"pid": os.getpid()}}
            if op == "prepare_iface":
                cmds = prepare_capture_iface(args["iface"], self.journal, apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "suppress_host_stack":
                cmds = suppress_host_stack(args["iface"], self.journal, apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "revert":
                import subprocess
                self.journal.revert(lambda c: subprocess.run(c, check=False))
                return {"ok": True, "data": {"reverted": True}}
            return {"ok": False, "error": f"unknown op: {op}"}
        except Exception as exc:  # never crash the helper on a bad request
            log.exception("op %s failed", op)
            return {"ok": False, "error": str(exc)}

    def serve(self) -> None:
        ensure_dirs()
        if HELPER_SOCKET.exists():
            HELPER_SOCKET.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
            # Create the socket with restrictive perms from the start — a
            # bind-then-chmod leaves a race window where a non-root local process
            # could connect and drive privileged network changes.
            old_umask = os.umask(0o077)
            try:
                srv.bind(str(HELPER_SOCKET))
            finally:
                os.umask(old_umask)
            os.chmod(HELPER_SOCKET, 0o600)
            srv.listen(4)
            log.info("privileged helper listening on %s", HELPER_SOCKET)
            while True:
                conn, _ = srv.accept()
                with conn:
                    buf = b""
                    while not buf.endswith(b"\n"):
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        buf += chunk
                    if not buf:
                        continue
                    resp = self.handle(decode_line(buf))
                    conn.sendall(encode(resp))


def main() -> int:
    setup_logging()
    if os.geteuid() != 0:
        log.warning("helper not running as root; privileged ops will fail")
    Helper().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
