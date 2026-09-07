"""Volume safeguards: hold limit, ordered overflow, auto-release, promotion."""

from __future__ import annotations

import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.core.bridge import UserspaceBridge
from reforge.core.intercept import InterceptQueue
from reforge.core.packet import Packet
from reforge.rules.actions import Hold
from reforge.rules.base import Rule, Verdict
from reforge.rules.derive import derive_actions, describe_actions
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter


def _frame(load: bytes, src: str = "10.0.0.1", dport: int = 80) -> bytes:
    return bytes(Ether() / IP(src=src, dst="10.0.0.2") / TCP(sport=5, dport=dport) / load)


def _bridge(iq: InterceptQueue) -> UserspaceBridge:
    eng = RuleEngine([Rule("h", parse_filter("TCP.dport == 80"), [Hold()])])
    return UserspaceBridge("ifa", "ifb", eng, intercept=iq, armed=True)


# ---- hold limit / overflow -------------------------------------------------
def test_hold_limit_caps_and_overflow_stays_in_order():
    iq = InterceptQueue(max_held=2, overflow="forward")
    br = _bridge(iq)
    eg: list = []
    for i in range(5):
        br._forward("ifa", _frame(f"m{i}".encode()), eg.append)
    assert len(iq.pending()) == 2                       # never holds more than the cap
    assert eg == []                                     # overflow queued behind held (same flow)
    p = iq.pending()
    iq.resolve(p[0].id, "forward")
    iq.resolve(p[1].id, "forward")
    assert [bytes(x)[-2:] for x in eg] == [b"m0", b"m1", b"m2", b"m3", b"m4"]


def test_overflow_on_unrelated_flow_forwards_immediately():
    iq = InterceptQueue(max_held=1, overflow="forward")
    br = _bridge(iq)
    eg: list = []
    br._forward("ifa", _frame(b"A", src="10.0.0.1"), eg.append)     # held (cap reached)
    br._forward("ifa", _frame(b"B", src="9.9.9.9"), eg.append)      # other flow -> immediate
    assert len(iq.pending()) == 1 and len(eg) == 1 and b"B" in eg[0]


def test_overflow_drop_policy():
    iq = InterceptQueue(max_held=1, overflow="drop")
    br = _bridge(iq)
    eg: list = []
    br._forward("ifa", _frame(b"A"), eg.append)         # held
    br._forward("ifa", _frame(b"B"), eg.append)         # over cap -> dropped
    assert iq.pending() and eg == [] and br.counters.dropped >= 1


# ---- auto-release ----------------------------------------------------------
def test_auto_release_forwards_stale_hold():
    iq = InterceptQueue(auto_release_s=0.05, overflow="forward")
    out: list = []
    iq.hold("ifa", b"X", lambda o: out.append(o), flow_key=("k", 1))
    assert out == []
    time.sleep(0.08)
    assert iq.reap() == 1
    assert out == [b"X"] and iq.count() == 0


def test_hold_returns_none_at_capacity():
    iq = InterceptQueue(max_held=1)
    assert iq.hold("ifa", b"A", lambda o: None, flow_key=("k", 1)) is not None
    assert iq.hold("ifa", b"B", lambda o: None, flow_key=("k", 2)) is None   # full


# ---- promotion (edit one -> apply to all + resends) ------------------------
def test_derive_payload_replace_applies_to_resend():
    o = _frame(b"user=admin&t=1")
    e = _frame(b"user=guest&t=1")
    actions = derive_actions(o, e)
    assert len(actions) == 1 and actions[0].__class__.__name__ == "PayloadReplace"
    assert "admin" in describe_actions(actions)
    # apply to a different, later packet containing the same pattern
    resend = Packet.from_bytes(_frame(b"GET user=admin now"), link="ether")
    actions[0].apply(resend, Verdict())
    assert b"user=guest now" in bytes(resend.scapy()[Raw].load)


def test_derive_header_field_change():
    o = _frame(b"x", dport=80)
    e = _frame(b"x", dport=8080)
    actions = derive_actions(o, e)
    assert any(a.__class__.__name__ == "SetField" and a.field == "dport" and a.value == 8080
               for a in actions)


def test_derive_no_change_returns_empty():
    o = _frame(b"same")
    assert derive_actions(o, o) == []
