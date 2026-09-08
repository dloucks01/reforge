"""TCP seq/ack fix-ups wired into the bridge forwarding path."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _grow_engine():
    # Grow any segment carrying "AAAAA" (5 bytes) to "BBBBBBBBBB" (10 bytes): +5.
    return RuleEngine([Rule("grow", M.AllMatch(), [A.PayloadReplace(b"AAAAA", b"BBBBBBBBBB")])])


def test_bridge_seqfix_shifts_later_seq_and_reverse_ack():
    br = UserspaceBridge("ethA", "ethB", _grow_engine(), seq_fixup=True)
    assert br.seq_fixup

    # Segment 1 (forward): carries the payload we grow by +5. Its own seq is
    # unchanged; the +5 delta is recorded for the rest of the flow.
    a1 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1000) / b"AAAAA")
    out1 = br.process_frame("ethA", a1)
    p1 = Ether(out1[0])
    assert bytes(p1[TCP].payload) == b"BBBBBBBBBB"    # grown
    assert p1[TCP].seq == 1000                         # own seq unshifted

    # Segment 2 (same direction, no payload change): seq 1005 -> 1010 (+5).
    a2 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1005) / b"CD")
    p2 = Ether(br.process_frame("ethA", a2)[0])
    assert p2[TCP].seq == 1010

    # Reverse segment acking our grown data: the peer received 10 bytes and acks
    # 1010 (grown coordinates); convert DOWN to the sender's 1005.
    b1 = bytes(Ether() / IP(src="10.0.0.2", dst="10.0.0.1")
               / TCP(sport=80, dport=1111, ack=1010))
    pb = Ether(br.process_frame("ethB", b1)[0])
    assert pb[TCP].ack == 1005


def test_bridge_seqfix_off_leaves_seq_untouched():
    br = UserspaceBridge("ethA", "ethB", _grow_engine(), seq_fixup=False)
    a1 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1000) / b"AAAAA")
    br.process_frame("ethA", a1)
    a2 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1005) / b"CD")
    p2 = Ether(br.process_frame("ethA", a2)[0])
    assert p2[TCP].seq == 1005     # no fix-up applied


def test_seqfixed_packet_has_valid_checksum():
    br = UserspaceBridge("ethA", "ethB", _grow_engine(), seq_fixup=True)
    a1 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1000) / b"AAAAA")
    br.process_frame("ethA", a1)
    a2 = bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2")
               / TCP(sport=1111, dport=80, seq=1005) / b"CD")
    out = br.process_frame("ethA", a2)[0]
    pkt = Ether(out)
    stored = pkt[TCP].chksum
    del pkt[TCP].chksum
    assert Ether(bytes(pkt))[TCP].chksum == stored   # checksum recomputed after seq shift
