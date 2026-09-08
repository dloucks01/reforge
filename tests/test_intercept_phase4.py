"""Phase 4: interception queue, hold parking, arm/pass-through, kill-switch."""

from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.core.intercept import InterceptQueue
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _frame(dport=80):
    return bytes(Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=dport) / b"hi")


# ---- InterceptQueue --------------------------------------------------------
def test_queue_forward_release():
    released = []
    q = InterceptQueue()
    hp = q.hold("ethA", b"\x01\x02", released.append)
    assert q.count() == 1
    assert q.drain_new() == [hp.id]
    assert q.resolve(hp.id, "forward")
    assert released == [b"\x01\x02"]      # released the original bytes
    assert q.count() == 0
    assert q.resolve(hp.id, "forward") is False  # already resolved


def test_queue_modify_and_drop():
    rel = []
    q = InterceptQueue()
    a = q.hold("ethA", b"aaaa", rel.append)
    b = q.hold("ethB", b"bbbb", rel.append)
    q.resolve(a.id, "modify", b"ZZZZ")
    q.resolve(b.id, "drop")
    assert rel == [b"ZZZZ", None]         # modified bytes, then drop (None)
    assert q.stats["modified"] == 1 and q.stats["dropped"] == 1


def test_release_all_killswitch():
    rel = []
    q = InterceptQueue()
    for i in range(3):
        q.hold("ethA", bytes([i]), rel.append)
    assert q.release_all("forward") == 3
    assert rel == [b"\x00", b"\x01", b"\x02"]
    assert q.count() == 0


# ---- bridge hold parking ---------------------------------------------------
def _hold_icmp_engine():
    return RuleEngine([Rule("hold-icmp", M.LayerMatch("ICMP"), [A.Hold()])])


def test_bridge_parks_held_packet_not_forwarded():
    q = InterceptQueue()
    br = UserspaceBridge("ethA", "ethB", _hold_icmp_engine(), intercept=q)
    sent = []
    icmp = bytes(Ether() / IP(dst="10.0.0.1") / ICMP())
    br._forward("ethA", icmp, sent.append)
    assert sent == []                     # held, not forwarded yet
    assert q.count() == 1
    assert br.counters.held == 1

    # resolving forward releases it on the original egress
    q.resolve(q.pending()[0].id, "forward")
    assert sent == [icmp]
    assert br.counters.forwarded == 1


def test_bridge_hold_modify_counts_modified():
    q = InterceptQueue()
    br = UserspaceBridge("ethA", "ethB", _hold_icmp_engine(), intercept=q)
    sent = []
    icmp = bytes(Ether() / IP(dst="10.0.0.1") / ICMP())
    br._forward("ethA", icmp, sent.append)
    q.resolve(q.pending()[0].id, "modify", b"\xde\xad")
    assert sent == [b"\xde\xad"]
    assert br.counters.modified == 1


# ---- arm / pass-through ----------------------------------------------------
def test_disarmed_bypasses_engine_and_holds():
    # A drop rule must NOT drop when the bridge is not armed (pure pass-through).
    engine = RuleEngine([Rule("drop", M.AllMatch(), [A.Drop()])])
    br = UserspaceBridge("ethA", "ethB", engine, armed=False)
    assert br.process_frame("ethA", _frame()) == [_frame()]
    assert br.counters.dropped == 0
    assert br.counters.forwarded == 1


def test_armed_applies_engine():
    engine = RuleEngine([Rule("drop", M.AllMatch(), [A.Drop()])])
    br = UserspaceBridge("ethA", "ethB", engine, armed=True)
    assert br.process_frame("ethA", _frame()) == []
    assert br.counters.dropped == 1
