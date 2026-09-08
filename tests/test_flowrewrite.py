"""R3: position-aware flow rewriter (edits shift only the segments after them)."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP

from reforge.core.bridge import UserspaceBridge
from reforge.core.flowrewrite import FlowRewriter
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _fseg(seq, dport=80):
    return IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=dport, seq=seq)


def _rseg(ack):
    return IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=1000, ack=ack)


def test_edit_shifts_only_later_segments():
    fr = FlowRewriter()
    # +5 byte edit recorded at forward position seq=2000
    fr.note_length_change(_fseg(2000), +5, orig_seq=2000)

    before = _fseg(1000)          # sits BEFORE the edit -> must NOT shift
    fr.apply(before)
    assert before[TCP].seq == 1000

    after = _fseg(3000)           # sits AFTER the edit -> shift +5
    fr.apply(after)
    assert after[TCP].seq == 3005


def test_reverse_ack_shifts_by_position():
    fr = FlowRewriter()
    fr.note_length_change(_fseg(2000), +5, orig_seq=2000)     # forward edit
    early = _rseg(1500)           # acks data before the edit -> unchanged
    fr.apply(early)
    assert early[TCP].ack == 1500
    late = _rseg(3000)            # acks grown data after the edit -> convert down by 5
    fr.apply(late)
    assert late[TCP].ack == 2995   # sender sent 5 fewer bytes; its ack is 5 lower


def test_retransmit_not_double_counted():
    fr = FlowRewriter()
    fr.note_length_change(_fseg(2000), +5, orig_seq=2000)
    fr.note_length_change(_fseg(2000), +5, orig_seq=2000)     # retransmit of same edit
    after = _fseg(3000)
    fr.apply(after)
    assert after[TCP].seq == 3005                              # +5, not +10


def test_multiple_edits_accumulate_downstream():
    fr = FlowRewriter()
    fr.note_length_change(_fseg(1000), +3, orig_seq=1000)
    fr.note_length_change(_fseg(2000), +4, orig_seq=2000)
    mid = _fseg(1500)             # only the first edit is before it
    fr.apply(mid)
    assert mid[TCP].seq == 1503
    end = _fseg(3000)             # both edits before it
    fr.apply(end)
    assert end[TCP].seq == 3007


def test_shrink_negative_delta():
    fr = FlowRewriter()
    fr.note_length_change(_fseg(2000), -4, orig_seq=2000)
    seg = _fseg(3000)
    fr.apply(seg)
    assert seg[TCP].seq == 2996


def test_bridge_flow_rewrite_uses_position_aware_fixer():
    engine = RuleEngine([Rule("grow", M.AllMatch(), [A.PayloadReplace(b"AAAAA", b"BBBBBBBBBB")])])
    br = UserspaceBridge("a", "b", engine, flow_rewrite=True)
    from reforge.core.flowrewrite import FlowRewriter as FR
    assert isinstance(br.seq_fixer, FR)


def test_reverse_ack_converts_down_full_roundtrip():
    """A grown forward segment means the receiver acks in grown coordinates; the
    original sender expects its own (smaller) coordinates, so the ack converts
    DOWN by the delta (regression guard for the reverse-ACK sign bug)."""
    fr = FlowRewriter()
    # forward edit at seq 1000 grew the stream by +16
    fr.note_length_change(_fseg(1000), +16, orig_seq=1000)
    # a later forward segment (orig seq 1014) shifts UP by 16 -> 1030
    fwd = _fseg(1014)
    fr.apply(fwd)
    assert fwd[TCP].seq == 1030
    # the receiver acks 1030 (grown); the sender expects 1014 -> convert DOWN
    ack = _rseg(1030)
    fr.apply(ack)
    assert ack[TCP].ack == 1014


def test_flowrewrite_handles_ipv6_flows():
    """seq/ack fix-up must work over IPv6 TCP (the flow key was IPv4-only, which
    threw 'Layer [IP] not found' and discarded all IPv6 manipulation)."""
    from scapy.layers.inet6 import IPv6

    def s6(seq, load=b""):
        p = IPv6(src="fd00::2", dst="fd00::1") / TCP(sport=80, dport=5000, seq=seq) / load
        return p
    def a6(ack):
        return IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5000, dport=80, ack=ack)

    fr = FlowRewriter()
    fr.note_length_change(s6(1000), +5, orig_seq=1000)
    fwd = s6(1010); fr.apply(fwd)
    assert fwd[TCP].seq == 1015                # later IPv6 segment shifted +5
    rev = a6(1015); fr.apply(rev)
    assert rev[TCP].ack == 1010                # reverse IPv6 ack converted down
