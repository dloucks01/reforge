"""Multi-core AF_PACKET capture via PACKET_FANOUT — the runnable fast path.

A single AF_PACKET socket (even with a TPACKET_V3 ring) drains on one CPU, so it
tops out a few Gbps below line rate on a busy link. PACKET_FANOUT tells the
kernel to load-balance incoming frames across a *group* of sockets; we open one
ring socket per worker, each drained on its own thread, so RX scales with cores.

This is a genuine higher-rate data plane in pure Python — no compiled component,
unlike the kernel-bypass backends (AF_XDP/PF_RING/DPDK, which still need their
per-deployment fast-path build; see docs/DEPLOYMENT.md). It reuses
RawSocketBackend for each group member (ring setup, drop stats, bytes-level
frames). Needs CAP_NET_RAW.

Fanout modes:
- hash  : balance by flow hash — keeps a flow on one worker (ordering-friendly).
- lb    : plain round-robin.
- cpu   : by the CPU that received the frame.
- rollover: spill to the next socket only when one is backlogged.
"""

from __future__ import annotations

import logging
import os
import queue
import struct
import threading
import time
from collections.abc import Iterable

from reforge.capture.base import BackendCaps, CaptureBackend, Frame
from reforge.capture.rawsocket import RawSocketBackend

log = logging.getLogger("reforge.fanout")

_SOL_PACKET = 263
_PACKET_FANOUT = 18
_FANOUT_MODES = {"hash": 0, "lb": 1, "cpu": 2, "rollover": 3}
_PACKET_FANOUT_FLAG_DEFRAG = 0x8000     # reassemble IP fragments before hashing


def fanout_arg(group_id: int, mode: str = "hash", defrag: bool = True) -> int:
    """Encode the __u32 PACKET_FANOUT argument: id (low 16) | type<<16 | flags."""
    m = _FANOUT_MODES.get(mode)
    if m is None:
        raise ValueError(f"unknown fanout mode: {mode!r}")
    arg = (group_id & 0xFFFF) | (m << 16)
    if defrag:
        arg |= (_PACKET_FANOUT_FLAG_DEFRAG << 16)
    return arg


def configure_fanout(sock, group_id: int, mode: str = "hash", defrag: bool = True) -> None:
    """Join `sock` to the PACKET_FANOUT group so the kernel load-balances to it."""
    arg = fanout_arg(group_id, mode, defrag)
    sock.setsockopt(_SOL_PACKET, _PACKET_FANOUT, struct.pack("=I", arg))


class FanoutRingBackend(CaptureBackend):
    caps = BackendCaps(
        name="af_packet_fanout",
        l2_rewrite=True,
        inject=True,
        max_speed_hint="5-10G (scales with cores)",
        needs_root=True,
        has_dataplane=True,        # unlike the kernel-bypass tier, this actually runs
        notes="AF_PACKET PACKET_FANOUT across N ring sockets; RX scales with CPU cores.",
    )

    def __init__(self, ifaces: list[str], workers: int | None = None,
                 mode: str = "hash", group_id: int | None = None,
                 use_ring: bool = True, queue_max: int = 200_000,
                 member_factory=None):
        if not ifaces:
            raise ValueError("FanoutRingBackend needs at least one interface")
        if mode not in _FANOUT_MODES:
            raise ValueError(f"unknown fanout mode: {mode!r}")
        self.ifaces = ifaces
        self.iface = ifaces[0]
        self.workers = max(1, workers or (os.cpu_count() or 2))
        self.mode = mode
        # a per-process default group id; all members share it to form one group
        self.group_id = group_id if group_id is not None else (os.getpid() & 0xFFFF)
        self.use_ring = use_ring
        self._member_factory = member_factory or self._default_member
        self._members: list = []
        self._threads: list[threading.Thread] = []
        self._q: queue.Queue = queue.Queue(maxsize=queue_max)
        self._running = threading.Event()
        self._q_dropped = 0

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        ok, note = RawSocketBackend.is_available()
        if not ok:
            return False, note
        return True, "AF_PACKET PACKET_FANOUT (multi-core RX; no compiled component)"

    def _default_member(self):
        return RawSocketBackend(self.ifaces, use_ring=self.use_ring)

    def open(self) -> None:  # pragma: no cover (needs CAP_NET_RAW)
        if self._members:
            return
        for _ in range(self.workers):
            m = self._member_factory()
            m.open()
            try:
                configure_fanout(m._sock, self.group_id, self.mode)
            except OSError as exc:
                log.warning("PACKET_FANOUT unavailable (%s); running a single socket", exc)
                self.workers = 1
                self._members = [m]
                break
            self._members.append(m)
        self._running.set()
        for m in self._members:
            t = threading.Thread(target=self._drain_member, args=(m,),
                                  name="reforge-fanout", daemon=True)
            t.start()
            self._threads.append(t)
        log.info("fanout capture: %d ring sockets in group %d (mode=%s)",
                 len(self._members), self.group_id, self.mode)

    def _drain_member(self, member) -> None:  # pragma: no cover (needs root + traffic)
        while self._running.is_set():
            for f in member.recv_burst(max_frames=256, timeout=0.2):
                try:
                    self._q.put_nowait(f)
                except queue.Full:
                    self._q_dropped += 1        # UI/consumer backpressure

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        """Pop aggregated frames the worker threads have queued from all members."""
        frames: list[Frame] = []
        deadline = time.monotonic() + timeout
        while len(frames) < max_frames:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                frames.append(self._q.get(timeout=remaining))
            except queue.Empty:
                break
        return frames

    def capture_stats(self) -> dict:
        """Aggregate kernel drop counters across the group + our queue drops."""
        received = dropped = 0
        for m in self._members:
            st = m.capture_stats()
            received += st.get("received", 0)
            dropped += st.get("dropped", 0)
        return {"received": received, "dropped": dropped,
                "queue_dropped": self._q_dropped}

    def send_burst(self, frames: Iterable[Frame]) -> int:
        if not self._members:                   # allow inject without a capture group
            self._members = [self._member_factory()]
        return self._members[0].send_burst(frames)

    def close(self) -> None:
        self._running.clear()
        for t in self._threads:
            t.join(timeout=1.0)
        self._threads.clear()
        for m in self._members:
            try:
                m.close()
            except Exception:
                pass
        self._members.clear()
