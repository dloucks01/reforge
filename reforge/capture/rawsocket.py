"""Raw AF_PACKET capture backend — faster hot path than Scapy's L2 socket.

Captures raw Ethernet frames straight off an AF_PACKET SOCK_RAW socket and hands
the pipeline plain bytes, with NO per-packet Scapy dissection on the receive
path (the pipeline dissects lazily, only when a rule or the GUI needs it). This
removes Scapy's parse overhead from the busiest loop — a real throughput win
over the default AfPacketBackend for typical links.

It is also the natural base for a PACKET_MMAP (TPACKETv3) zero-copy upgrade. The
kernel-bypass backends (AF_XDP/PF_RING/DPDK) still need their compiled fast-path
component; see docs/DEPLOYMENT.md. Needs CAP_NET_RAW.
"""

from __future__ import annotations

import select
import socket
import struct
import sys
import time
from typing import Iterable

from reforge.capture.base import BackendCaps, CaptureBackend, Frame

_ETH_P_ALL = 0x0003
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_DROP_MEMBERSHIP = 2
_PACKET_MR_PROMISC = 1


class RawSocketBackend(CaptureBackend):
    caps = BackendCaps(
        name="raw_afpacket",
        l2_rewrite=True,
        inject=True,
        max_speed_hint="2-5G",
        needs_root=True,
        notes="Raw AF_PACKET; bytes-level capture, no Scapy on the hot path.",
    )

    def __init__(self, ifaces: list[str], bpf: str | None = None):
        if not ifaces:
            raise ValueError("RawSocketBackend needs at least one interface")
        self.ifaces = ifaces
        self.iface = ifaces[0]
        self._sock: socket.socket | None = None
        self._senders: dict[str, socket.socket] = {}

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
            return False, "AF_PACKET not available (needs Linux)"
        return True, "raw AF_PACKET (bytes-level, no Scapy on capture)"

    def _promisc(self, sock: socket.socket, iface: str, on: bool) -> None:
        try:
            idx = socket.if_nametoindex(iface)
            mreq = struct.pack("iHH8s", idx, _PACKET_MR_PROMISC, 0, b"")
            opt = _PACKET_ADD_MEMBERSHIP if on else _PACKET_DROP_MEMBERSHIP
            sock.setsockopt(_SOL_PACKET, opt, mreq)
        except OSError:
            pass

    def open(self) -> None:
        if self._sock is not None:
            return
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        s.bind((self.iface, 0))
        s.setblocking(False)
        self._promisc(s, self.iface, True)
        self._sock = s

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        if self._sock is None:
            self.open()
        frames: list[Frame] = []
        deadline = time.monotonic() + timeout
        while len(frames) < max_frames:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            readable, _, _ = select.select([self._sock], [], [], remaining)
            if not readable:
                break
            try:
                data = self._sock.recv(65535)
            except BlockingIOError:
                continue
            except OSError:
                break
            if data:
                frames.append(Frame(data=data, ingress=self.iface, meta={"ts": time.time()}))
        return frames

    def _sender(self, iface: str) -> socket.socket:
        if iface not in self._senders:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            s.bind((iface, 0))
            self._senders[iface] = s
        return self._senders[iface]

    def send_burst(self, frames: Iterable[Frame]) -> int:
        sent = 0
        for f in frames:
            iface = f.egress or (self.ifaces[1] if len(self.ifaces) > 1 else self.iface)
            try:
                self._sender(iface).send(f.data)
                sent += 1
            except OSError:
                pass
        return sent

    def close(self) -> None:
        if self._sock is not None:
            self._promisc(self._sock, self.iface, False)
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        for s in self._senders.values():
            try:
                s.close()
            except OSError:
                pass
        self._senders.clear()
