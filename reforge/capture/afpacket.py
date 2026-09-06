"""AF_PACKET capture backend (Phase 1: real single-interface passive capture).

Uses Scapy's L2 sockets. Capture reads from a promiscuous L2 listen socket on
one interface with an optional BPF filter; send uses an L2 socket (used from
Phase 3 for the inline bridge). Needs CAP_NET_RAW (root or the privileged
helper).

Throughput note: this is the compatibility floor (~1-2 Gbps). AF_XDP/PF_RING/
DPDK backends (Phase 8) implement the same interface for higher speeds.
"""

from __future__ import annotations

import select
import time
from typing import Iterable

from reforge.capture.base import BackendCaps, CaptureBackend, Frame


class AfPacketBackend(CaptureBackend):
    caps = BackendCaps(
        name="af_packet",
        l2_rewrite=True,
        inject=True,
        max_speed_hint="1-2G",
        needs_root=True,
        notes="Universal fallback; works on any NIC/driver.",
    )

    def __init__(self, ifaces: list[str], bpf: str | None = None):
        if not ifaces:
            raise ValueError("AfPacketBackend needs at least one interface")
        self.ifaces = ifaces
        self.capture_iface = ifaces[0]  # Phase 1 captures on a single interface
        self.bpf = bpf
        self._listen = None
        self._senders: dict[str, object] = {}

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        try:
            import scapy  # noqa: F401
        except Exception as exc:  # pragma: no cover
            return False, f"scapy import failed: {exc}"
        return True, "scapy present; AF_PACKET usable with CAP_NET_RAW"

    def open(self) -> None:
        from scapy.all import conf

        if self._listen is None:
            self._listen = conf.L2listen(iface=self.capture_iface, filter=self.bpf)

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        if self._listen is None:
            self.open()
        frames: list[Frame] = []
        deadline = time.monotonic() + timeout
        while len(frames) < max_frames:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([self._listen], [], [], remaining)
            if not readable:
                break
            pkt = self._listen.recv()
            if pkt is None:
                continue
            ts = float(getattr(pkt, "time", time.time()))
            frames.append(
                Frame(data=bytes(pkt), ingress=self.capture_iface, meta={"ts": ts})
            )
        return frames

    def _sender(self, iface: str):
        from scapy.all import conf

        if iface not in self._senders:
            self._senders[iface] = conf.L2socket(iface=iface)
        return self._senders[iface]

    def send_burst(self, frames: Iterable[Frame]) -> int:
        from scapy.layers.l2 import Ether

        sent = 0
        for f in frames:
            iface = f.egress or (self.ifaces[1] if len(self.ifaces) > 1 else self.ifaces[0])
            self._sender(iface).send(Ether(f.data))
            sent += 1
        return sent

    def close(self) -> None:
        for sock in [self._listen, *self._senders.values()]:
            try:
                if sock is not None:
                    sock.close()  # type: ignore[union-attr]
            except Exception:
                pass
        self._listen = None
        self._senders.clear()
