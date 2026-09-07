"""Passive TCP stream reassembler.

Reconstructs each direction of a TCP connection into an in-order byte stream,
handling out-of-order segments, retransmissions, and front overlaps (32-bit SEQ
wraparound aware). Feeds content consumers (HTTP framer, credential harvester)
that need complete application data spanning multiple segments.

Passive/inspection only — no re-injection. See docs/REASSEMBLY-PLAN.md.
"""

from __future__ import annotations

from typing import Callable

_MOD = 1 << 32
_HALF = 1 << 31


def _sub(a: int, b: int) -> int:
    return (a - b) % _MOD


def before(a: int, b: int) -> bool:
    """True if SEQ a is strictly before b (RFC 1982 serial comparison)."""
    d = _sub(b, a)
    return 0 < d < _HALF


def after(a: int, b: int) -> bool:
    return before(b, a)


class DirectionBuffer:
    """In-order reassembly for one direction of a flow."""

    def __init__(self, max_pending: int = 2048):
        self.next: int | None = None            # next expected SEQ (absolute)
        self.pending: dict[int, bytes] = {}     # seq -> data (out of order)
        self.max_pending = max_pending

    def set_isn(self, seq: int) -> None:
        if self.next is None:
            self.next = seq

    def add(self, seq: int, data: bytes) -> bytes:
        """Add a segment; return any newly-contiguous bytes (possibly b"")."""
        if not data:
            return b""
        if self.next is None:
            self.next = seq
        end = (seq + len(data)) % _MOD

        # fully-old retransmit (ends at or before next)
        if not after(end, self.next):
            return self._drain()

        # front overlap: trim the already-delivered prefix
        if before(seq, self.next):
            trim = _sub(self.next, seq)
            data = data[trim:]
            seq = self.next

        if seq == self.next:
            out = bytearray(data)
            self.next = (self.next + len(data)) % _MOD
            out += self._drain()
            return bytes(out)

        # future segment: buffer out of order (keep the longer on a dup seq)
        if seq not in self.pending or len(data) > len(self.pending[seq]):
            if len(self.pending) < self.max_pending:
                self.pending[seq] = data
        return b""

    def _drain(self) -> bytes:
        """Pull any buffered segments now contiguous with `next`."""
        out = bytearray()
        while self.pending:
            best = None
            for p, d in self.pending.items():
                end = (p + len(d)) % _MOD
                starts_ok = (p == self.next) or before(p, self.next)
                extends = after(end, self.next)
                if starts_ok and extends:
                    best = p
                    break
                if not extends:            # fully old buffered segment
                    self.pending.pop(p)
                    break
            else:
                break
            if best is None:
                continue
            d = self.pending.pop(best)
            trim = _sub(self.next, best)
            seg = d[trim:]
            out += seg
            self.next = (self.next + len(seg)) % _MOD
        return bytes(out)


class TcpReassembler:
    """Reassembles both directions of all observed TCP flows."""

    def __init__(self, on_data: Callable[[tuple, bytes], None] | None = None):
        from reforge.core.scapy_init import warmup
        warmup()
        self.dirs: dict[tuple, DirectionBuffer] = {}
        self.on_data = on_data
        self.closed: set[tuple] = set()

    def process(self, pkt) -> list[tuple[tuple, bytes]]:
        """Feed a Scapy packet; return list of (flow_key, newly_contiguous_bytes)."""
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6

        if not pkt.haslayer(TCP):
            return []
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return []
        tcp = pkt.getlayer(TCP)
        key = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
        buf = self.dirs.setdefault(key, DirectionBuffer())

        flags = int(tcp.flags)
        if flags & 0x02:                         # SYN: data starts at seq+1
            buf.set_isn((int(tcp.seq) + 1) % _MOD)

        results: list[tuple[tuple, bytes]] = []
        payload = bytes(tcp.payload)
        if payload:
            delivered = buf.add(int(tcp.seq), payload)
            if delivered:
                results.append((key, delivered))
                if self.on_data:
                    self.on_data(key, delivered)

        if flags & 0x05:                         # FIN or RST: mark torn down
            self.closed.add(key)
        return results

    def evict(self, keys: list[tuple] | None = None) -> None:
        for k in (keys if keys is not None else list(self.closed)):
            self.dirs.pop(k, None)
            self.closed.discard(k)
