"""Stateful TCP sequence/ack fix-ups (advanced, flag-gated).

When an inline edit changes the length of a TCP segment's payload, every later
segment in that flow is off by the accumulated delta: the sender's own SEQ and
the peer's ACK must be shifted to keep the connection in sync. Getting this
wrong desyncs the flow, so this lives in its own module, is exhaustively tested,
and is applied only when explicitly enabled.

Model: per directional 4-tuple (src_ip, sport, dst_ip, dport) we track the
cumulative byte delta we've introduced in that direction. For any packet:
  - shift SEQ by the delta accumulated in the SAME direction (bytes we added
    before this segment's data), and
  - shift ACK by the delta accumulated in the REVERSE direction (extra bytes the
    peer has now received from us).
"""

from __future__ import annotations

from dataclasses import dataclass, field

_MASK = 0xFFFFFFFF


def _fwd_key(pkt):
    from scapy.layers.inet import IP, TCP

    ip, tcp = pkt[IP], pkt[TCP]
    return (ip.src, tcp.sport, ip.dst, tcp.dport)


def _rev_key(pkt):
    from scapy.layers.inet import IP, TCP

    ip, tcp = pkt[IP], pkt[TCP]
    return (ip.dst, tcp.dport, ip.src, tcp.sport)


@dataclass
class TcpSeqFixer:
    deltas: dict = field(default_factory=dict)   # directional key -> cumulative delta

    def note_length_change(self, pkt, delta: int) -> None:
        """Record that we changed this segment's payload length by `delta`.

        Applies from the NEXT segment onward in the same direction, so we record
        it against the forward key but do not shift this packet's own seq.
        """
        if delta == 0:
            return
        key = _fwd_key(pkt)
        self.deltas[key] = self.deltas.get(key, 0) + delta

    def apply(self, pkt) -> bool:
        """Shift SEQ/ACK of a TCP packet by tracked deltas. Returns True if changed."""
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return False
        tcp = pkt[TCP]
        changed = False
        fwd = self.deltas.get(_fwd_key(pkt), 0)
        if fwd:
            tcp.seq = (tcp.seq + fwd) & _MASK
            changed = True
        rev = self.deltas.get(_rev_key(pkt), 0)
        if rev:
            tcp.ack = (tcp.ack + rev) & _MASK
            changed = True
        return changed
