"""Raw AF_PACKET capture backend — faster hot path than Scapy's L2 socket.

Captures raw Ethernet frames straight off an AF_PACKET SOCK_RAW socket and hands
the pipeline plain bytes, with NO per-packet Scapy dissection on the receive
path (the pipeline dissects lazily, only when a rule or the GUI needs it). This
removes Scapy's parse overhead from the busiest loop — a real throughput win
over the default AfPacketBackend for typical links.

For high pps it can read from a kernel-mapped TPACKET_V3 RX ring (PACKET_MMAP)
instead of one recv() per packet, and it always exposes the kernel's own drop
counters (`capture_stats()`) so the operator sees loss the moment the NIC/kernel
can't keep up — the honest high-rate signal a passive tap needs. Ring setup
falls back cleanly to plain recv() if the kernel/driver won't grant it. The
kernel-bypass backends (AF_XDP/PF_RING/DPDK) still need their compiled fast-path
component; see docs/DEPLOYMENT.md. Needs CAP_NET_RAW.
"""

from __future__ import annotations

import logging
import mmap
import select
import socket
import struct
import sys
import time
from collections.abc import Iterable

from reforge.capture import mmap_ring as ring
from reforge.capture.base import BackendCaps, CaptureBackend, Frame

log = logging.getLogger("reforge.rawsocket")

_ETH_P_ALL = 0x0003
_SOL_PACKET = 263
_PACKET_ADD_MEMBERSHIP = 1
_PACKET_DROP_MEMBERSHIP = 2
_PACKET_MR_PROMISC = 1

_DEFAULT_RCVBUF = 8 * 1024 * 1024        # 8 MiB socket buffer to ride out bursts
_RING_BLOCK_SIZE = 1 << 20               # 1 MiB blocks
_RING_BLOCK_COUNT = 8                     # 8 MiB ring
_RING_FRAME_SIZE = 2048


class RawSocketBackend(CaptureBackend):
    caps = BackendCaps(
        name="raw_afpacket",
        l2_rewrite=True,
        inject=True,
        max_speed_hint="2-5G",
        needs_root=True,
        notes="Raw AF_PACKET; bytes-level capture, mmap ring + kernel drop stats.",
    )

    def __init__(self, ifaces: list[str], bpf: str | None = None,
                 rcvbuf: int = _DEFAULT_RCVBUF, use_ring: bool = True):
        if not ifaces:
            raise ValueError("RawSocketBackend needs at least one interface")
        self.ifaces = ifaces
        self.iface = ifaces[0]
        self.rcvbuf = rcvbuf
        self.use_ring = use_ring
        self._sock: socket.socket | None = None
        self._senders: dict[str, socket.socket] = {}
        # ring state (only when the mmap fast path is active)
        self._ring: mmap.mmap | None = None
        self._block_off = 0
        # cumulative kernel counters (PACKET_STATISTICS is read-and-reset)
        self._kern_packets = 0
        self._kern_drops = 0

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_PACKET"):
            return False, "AF_PACKET not available (needs Linux)"
        return True, "raw AF_PACKET (bytes-level, mmap ring + drop stats)"

    def _promisc(self, sock: socket.socket, iface: str, on: bool) -> None:
        try:
            idx = socket.if_nametoindex(iface)
            mreq = struct.pack("iHH8s", idx, _PACKET_MR_PROMISC, 0, b"")
            opt = _PACKET_ADD_MEMBERSHIP if on else _PACKET_DROP_MEMBERSHIP
            sock.setsockopt(_SOL_PACKET, opt, mreq)
        except OSError:
            pass

    def open(self) -> None:  # pragma: no cover (needs CAP_NET_RAW)
        if self._sock is not None:
            return
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(_ETH_P_ALL))
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.rcvbuf)
        except OSError:
            pass
        if self.use_ring:
            self._setup_ring(s)          # sets self._ring, or falls back to recv()
        s.bind((self.iface, 0))
        s.setblocking(False)
        self._promisc(s, self.iface, True)
        self._sock = s

    def _setup_ring(self, s: socket.socket) -> None:  # pragma: no cover (needs root)
        """Try to attach a TPACKET_V3 RX ring; on any failure, use plain recv()."""
        try:
            s.setsockopt(ring.SOL_PACKET, ring.PACKET_VERSION, ring.TPACKET_V3)
            req = ring.build_tpacket_req3(_RING_BLOCK_SIZE, _RING_BLOCK_COUNT,
                                          _RING_FRAME_SIZE)
            s.setsockopt(ring.SOL_PACKET, ring.PACKET_RX_RING, req)
            self._ring = mmap.mmap(s.fileno(), _RING_BLOCK_SIZE * _RING_BLOCK_COUNT,
                                   mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
            self._block_off = 0
            log.info("raw AF_PACKET: TPACKET_V3 ring active (%d x %d MiB)",
                     _RING_BLOCK_COUNT, _RING_BLOCK_SIZE >> 20)
        except OSError as exc:
            self._ring = None
            log.info("mmap ring unavailable (%s); using plain recv()", exc)

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        if self._sock is None:
            self.open()
        if self._ring is not None:
            return self._recv_ring(max_frames, timeout)   # pragma: no cover
        return self._recv_plain(max_frames, timeout)

    def _recv_plain(self, max_frames: int, timeout: float) -> list[Frame]:
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

    def _recv_ring(self, max_frames: int, timeout: float) -> list[Frame]:  # pragma: no cover
        """Drain ready TPACKET_V3 blocks from the mmap ring."""
        frames: list[Frame] = []
        deadline = time.monotonic() + timeout
        while len(frames) < max_frames:
            if ring.block_status(self._ring, self._block_off) & ring.TP_STATUS_USER:
                for rf in ring.walk_block(self._ring, self._block_off):
                    frames.append(Frame(data=rf.data, ingress=self.iface,
                                        meta={"ts": rf.sec + rf.nsec / 1e9}))
                ring.set_block_status(self._ring, self._block_off, ring.TP_STATUS_KERNEL)
                self._block_off = (self._block_off + _RING_BLOCK_SIZE) % \
                    (_RING_BLOCK_SIZE * _RING_BLOCK_COUNT)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            select.select([self._sock], [], [], remaining)
        return frames

    def capture_stats(self) -> dict:
        """Cumulative kernel counters for this socket: received / dropped.

        PACKET_STATISTICS is read-and-reset in the kernel, so we accumulate.
        Returns zeros if the socket isn't open or the kernel refuses the query.
        """
        if self._sock is not None:
            try:
                raw = self._sock.getsockopt(_SOL_PACKET, ring.PACKET_STATISTICS, 16)
                pkts, drops = ring.parse_tpacket_stats(raw)
                self._kern_packets += pkts
                self._kern_drops += drops
            except OSError:
                pass
        return {"received": self._kern_packets, "dropped": self._kern_drops}

    def _sender(self, iface: str) -> socket.socket:  # pragma: no cover (needs root)
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
        if self._ring is not None:
            try:
                self._ring.close()
            except (OSError, ValueError):
                pass
            self._ring = None
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
