"""Position-aware TCP flow rewriter (reassembly R3).

The simple TcpSeqFixer tracks a single cumulative delta per direction and shifts
*every* segment by it — wrong for a segment whose data sits BEFORE an edit
(e.g. an older retransmit), which must not be shifted. This rewriter records each
length-changing edit at its original sequence position and shifts a segment only
by the edits that occur strictly before it:

  new SEQ = SEQ + sum(delta for edits in this direction with pos < SEQ)
  new ACK = ACK - sum(delta for edits in the reverse direction with pos < ACK)

Edits are de-duplicated by (direction, original SEQ) so retransmissions aren't
counted twice. Same interface as TcpSeqFixer, so it drops into apply_engine and
the bridge unchanged.

Scope: bounded, in-order, single-segment-contained edits (retransmit-correct).
Content edits spanning multiple segments still need the R2 proxy path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_MOD = 1 << 32
_HALF = 1 << 31


def _before(a: int, b: int) -> bool:
    d = (b - a) % _MOD
    return 0 < d < _HALF


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
class FlowRewriter:
    # direction key -> {original_seq: delta}
    edits: dict = field(default_factory=dict)

    def note_length_change(self, pkt, delta: int, orig_seq: int | None = None) -> None:
        """Record an edit of `delta` bytes at this segment's original position."""
        if delta == 0:
            return
        from scapy.layers.inet import TCP

        key = _fwd_key(pkt)
        seq = orig_seq if orig_seq is not None else pkt[TCP].seq
        d = self.edits.setdefault(key, {})
        if seq in d:                       # retransmit of an already-counted edit
            return
        d[seq] = delta

    def _shift(self, key: tuple, point: int) -> int:
        """Sum of deltas for edits in `key` positioned strictly before `point`."""
        total = 0
        for pos, delta in self.edits.get(key, {}).items():
            if _before(pos, point):
                total += delta
        return total

    def apply(self, pkt) -> bool:
        """Shift this segment's SEQ/ACK by position-appropriate deltas."""
        from scapy.layers.inet import TCP

        if not pkt.haslayer(TCP):
            return False
        tcp = pkt[TCP]
        changed = False
        sseq = self._shift(_fwd_key(pkt), tcp.seq)
        if sseq:
            tcp.seq = (tcp.seq + sseq) % _MOD
            changed = True
        # ACKs run the other way: the receiver acks positions in the *rewritten*
        # (grown/shrunk) reverse stream, but the original sender expects acks in
        # its own coordinates, so subtract the reverse-direction delta.
        rkey = _rev_key(pkt)
        sack = self._shift(rkey, tcp.ack)
        if sack:
            tcp.ack = (tcp.ack - sack) % _MOD
            changed = True
        if self._fix_sack_edges(tcp, rkey):
            changed = True
        return changed

    def _fix_sack_edges(self, tcp, rkey: tuple) -> bool:
        """SACK blocks carry sequence numbers in the reverse stream too; convert
        each edge to the original sender's coordinates like the ACK."""
        opts = tcp.options
        if not opts:
            return False
        changed = False
        new_opts = []
        for name, val in opts:
            if name == "SAck" and isinstance(val, (tuple, list)) and val:
                shifted = tuple((int(e) - self._shift(rkey, int(e))) % _MOD for e in val)
                new_opts.append((name, shifted))
                if shifted != tuple(val):
                    changed = True
            else:
                new_opts.append((name, val))
        if changed:
            tcp.options = new_opts
        return changed
