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
  - shift ACK down by the delta accumulated in the REVERSE direction: the peer
    acks positions in the stream we grew/shrank, so convert its ack back to the
    original sender's coordinates.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_MASK = 0xFFFFFFFF


def _ip_tcp(pkt):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6

    return (pkt.getlayer(IP) or pkt.getlayer(IPv6)), pkt[TCP]


def _fwd_key(pkt):
    ip, tcp = _ip_tcp(pkt)
    return (ip.src, tcp.sport, ip.dst, tcp.dport)


def _rev_key(pkt):
    ip, tcp = _ip_tcp(pkt)
    return (ip.dst, tcp.dport, ip.src, tcp.sport)


@dataclass
class TcpSeqFixer:
    deltas: dict = field(default_factory=dict)   # directional key -> cumulative delta
    _seen: set = field(default_factory=set)      # (fwd_key, orig_seq) already counted

    def note_length_change(self, pkt, delta: int, orig_seq: int | None = None) -> None:
        """Record that we changed this segment's payload length by `delta`.

        Applies from the NEXT segment onward in the same direction. Deduplicated
        by (flow, original sequence) so a RETRANSMISSION of the same segment
        isn't counted twice (which would corrupt the stream).

        NOTE: this is the clean-flow model. Robust handling of overlapping /
        partially-retransmitted / out-of-order segments needs per-flow byte-range
        tracking and is future work — keep seq-fixup for controlled flows.
        """
        if delta == 0:
            return
        from scapy.layers.inet import TCP

        key = _fwd_key(pkt)
        seq = orig_seq if orig_seq is not None else pkt[TCP].seq
        if (key, seq) in self._seen:
            return                       # retransmit of an already-counted segment
        self._seen.add((key, seq))
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
            # the peer acks positions in the stream we grew/shrank; convert its
            # ack back to the original sender's coordinates by subtracting.
            tcp.ack = (tcp.ack - rev) & _MASK
            changed = True
        return changed
