"""In-order interception release: held packets never let the stream reorder."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.core.intercept import InterceptQueue
from reforge.rules.actions import Hold
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter

FLOW = ("ifa", "10.0.0.1", 5, "10.0.0.2", 80, "TCP")


# ---- queue level -----------------------------------------------------------
def test_passthrough_queues_behind_held_and_releases_in_order():
    q = InterceptQueue()
    out: list = []
    h = q.hold("ifa", b"P1", lambda o: out.append(("P1", o)), flow_key=FLOW)
    assert q.passthrough("ifa", b"P2", lambda o: out.append(("P2", o)), FLOW) is True
    assert out == []                                   # P2 must wait behind held P1
    q.resolve(h.id, "modify", b"P1*")
    assert out == [("P1", b"P1*"), ("P2", b"P2")]      # edited P1 first, then P2


def test_unrelated_flow_not_blocked():
    q = InterceptQueue()
    q.hold("ifa", b"A", lambda o: None, flow_key=FLOW)
    other = ("ifa", "9.9.9.9", 1, "8.8.8.8", 53, "UDP")
    # a different flow has nothing queued -> caller sends immediately
    assert q.passthrough("ifa", b"B", lambda o: None, other) is False


def test_out_of_order_resolve_still_egresses_in_order():
    q = InterceptQueue()
    out: list = []
    a = q.hold("ifa", b"A", lambda o: out.append("A"), flow_key=FLOW)
    b = q.hold("ifa", b"B", lambda o: out.append("B"), flow_key=FLOW)
    q.resolve(b.id, "forward")                          # resolve the 2nd first
    assert out == []                                    # B may not overtake A
    q.resolve(a.id, "forward")
    assert out == ["A", "B"]


def test_drop_head_releases_rest():
    q = InterceptQueue()
    out: list = []
    a = q.hold("ifa", b"A", lambda o: out.append(("A", o)), flow_key=FLOW)
    q.passthrough("ifa", b"B", lambda o: out.append(("B", o)), FLOW)
    q.resolve(a.id, "drop")
    assert out == [("A", None), ("B", b"B")]            # A dropped, B still forwarded


def test_flow_key_none_blocks_nothing():
    q = InterceptQueue()
    out: list = []
    q.hold("ifa", b"A", lambda o: out.append("A"), flow_key=None)   # opt out of ordering
    # a None-keyed hold occupies its own flow, so a keyed passthrough is unaffected
    assert q.passthrough("ifa", b"B", lambda o: out.append("B"), FLOW) is False


# ---- bridge level ----------------------------------------------------------
def _frame(load: bytes) -> bytes:
    return bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5, dport=80) / load)


def _bridge(expr: str):
    eng = RuleEngine([Rule("hold", parse_filter(expr), [Hold()])])
    iq = InterceptQueue()
    return UserspaceBridge("ifa", "ifb", eng, intercept=iq, armed=True), iq


def test_bridge_holds_matching_and_orders_stream():
    # filter catches only the first message; the second same-flow packet forwards
    # but must not overtake the held first.
    br, iq = _bridge('Raw.load contains "first"')
    egress: list = []
    br._forward("ifa", _frame(b"first"), egress.append)     # HELD
    br._forward("ifa", _frame(b"second"), egress.append)    # queued behind it
    assert egress == []
    assert len(iq.pending()) == 1                            # only 'first' is operator-held
    iq.resolve(iq.pending()[0].id, "modify", _frame(b"FIRSTMOD"))
    assert len(egress) == 2
    assert b"FIRSTMOD" in egress[0] and b"second" in egress[1]


def test_bridge_all_held_release_in_arrival_order():
    br, iq = _bridge("TCP.dport == 80")
    egress: list = []
    br._forward("ifa", _frame(b"one"), egress.append)
    br._forward("ifa", _frame(b"two"), egress.append)
    held = iq.pending()
    assert len(held) == 2
    iq.resolve(held[1].id, "forward")                       # resolve 2nd first
    assert egress == []                                     # 2nd waits for 1st
    iq.resolve(held[0].id, "forward")
    assert b"one" in egress[0] and b"two" in egress[1]
