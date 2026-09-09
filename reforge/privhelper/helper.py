"""Privileged helper process.

Runs with elevated privileges (CAP_NET_ADMIN), listens on a local root-owned
Unix socket, and performs the privileged network CONFIG the app needs: interface
prep, transparent-bridge prep + host-stack suppression, NFQUEUE rule install /
remove, fail-open/closed, and teardown/revert.

Privilege model: this helper does the stateless config (nft/ip/ethtool). The
capture/bridge data plane still runs in the app process, which needs CAP_NET_RAW
for packet I/O — that cannot be delegated over an IPC. So the helper reduces, but
does not eliminate, the app's privileges. Use HelperClient (ipc.py) to drive it;
when no helper socket is present the CLI applies the same commands directly (it
already requires root for capture).

Run:  sudo python -m reforge.privhelper.helper
"""

from __future__ import annotations

import logging
import os
import socket

from reforge.constants import HELPER_SOCKET, ensure_dirs
from reforge.logging_setup import setup_logging
from reforge.privhelper.ipc import decode_line, encode
from reforge.privhelper.netconfig import (
    RevertJournal,
    fail_closed_commands,
    fail_open_commands,
    prepare_bridge,
    prepare_capture_iface,
    suppress_host_stack,
)

log = logging.getLogger("reforge.helper")

# Cap the per-request read so a client that never sends a newline can't make the
# helper buffer without bound.
_MAX_REQUEST = 1 << 20


class Helper:
    def __init__(self):
        self.journal = RevertJournal()
        self._queue_remove: list[list[str]] = []

    def _apply(self, cmds: list[list[str]]) -> None:
        import subprocess
        for cmd in cmds:
            subprocess.run(cmd, capture_output=True, check=False)

    def handle(self, req: dict) -> dict:
        op = req.get("op")
        args = req.get("args", {})
        try:
            if op == "ping":
                return {"ok": True, "data": {"pid": os.getpid()}}
            if op == "prepare_iface":
                cmds = prepare_capture_iface(args["iface"], self.journal, apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "prepare_bridge":
                cmds = prepare_bridge(args["if_a"], args["if_b"], self.journal,
                                      apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "suppress_host_stack":
                cmds = suppress_host_stack(args["iface"], self.journal, apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "fail_open":
                cmds = fail_open_commands(args["if_a"], args["if_b"], self.journal,
                                          apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "fail_closed":
                cmds = fail_closed_commands(args["if_a"], args["if_b"], self.journal,
                                            apply=args.get("apply", False))
                return {"ok": True, "data": {"planned": cmds}}
            if op == "queue_install":
                from reforge.capture.nfqueue import nft_forward_queue_rules
                install, remove = nft_forward_queue_rules(args.get("queue_num", 1),
                                                          args.get("victims") or None)
                if args.get("apply", False):
                    self._apply(install)
                    self._queue_remove = remove
                return {"ok": True, "data": {"planned": install, "remove": remove}}
            if op == "queue_remove":
                if args.get("apply", False) and self._queue_remove:
                    self._apply(self._queue_remove)
                    self._queue_remove = []
                return {"ok": True, "data": {"removed": True}}
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
                        if len(buf) > _MAX_REQUEST:      # bound a runaway client
                            buf = b""
                            break
                    if not buf:
                        continue
                    try:
                        resp = self.handle(decode_line(buf))
                    except Exception as exc:             # malformed JSON, etc.
                        resp = {"ok": False, "error": f"bad request: {exc}"}
                    conn.sendall(encode(resp))


def main() -> int:
    setup_logging()
    if os.geteuid() != 0:
        log.warning("helper not running as root; privileged ops will fail")
    Helper().serve()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
