"""NFQUEUE runner: rule verdicts + interactive hold (deferred verdict) + rules."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP

from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules
from reforge.core.intercept import InterceptQueue
from reforge.rules.actions import Drop, Hold, SetField
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter


class FakePkt:
    def __init__(self, payload):
        self._p = payload
        self.verdict = None
        self.out = None

    def get_payload(self):
        return self._p

    def set_payload(self, b):
        self.out = b

    def accept(self):
        self.verdict = "accept"

    def drop(self):
        self.verdict = "drop"


def _ip(dport=80, load=b"GET /"):
    return bytes(IP(src="10.0.0.50", dst="10.0.0.9") / TCP(sport=5, dport=dport) / load)


def test_nfqueue_rule_modify_and_drop():
    r = NfqueueRunner(RuleEngine([Rule("rw", parse_filter("TCP.dport == 80"),
                                       [SetField("IP", "dst", "10.0.0.99")])]))
    p = FakePkt(_ip())
    r.process(p)
    assert p.verdict == "accept" and p.out is not None
    assert IP(p.out).dst == "10.0.0.99"

    d = NfqueueRunner(RuleEngine([Rule("d", parse_filter("TCP.dport == 80"), [Drop()])]))
    pd = FakePkt(_ip())
    d.process(pd)
    assert pd.verdict == "drop"


def test_nfqueue_hold_defers_verdict_until_resolve():
    iq = InterceptQueue()
    r = NfqueueRunner(RuleEngine([Rule("h", parse_filter("TCP.dport == 80"), [Hold()])]),
                      intercept=iq)
    p = FakePkt(_ip())
    r.process(p)
    assert p.verdict is None and iq.count() == 1          # verdict deferred
    hp = iq.pending()[0]
    assert hp.link == "ip"
    edited = _ip(load=b"GET /x")
    iq.resolve(hp.id, "modify", edited)
    assert p.verdict == "accept" and p.out == edited      # verdict issued on resolve


def test_nfqueue_hold_overflow_drops_at_capacity():
    iq = InterceptQueue(max_held=1, overflow="drop")
    iq.hold("x", b"filler", lambda o: None, flow_key=("z", 9))   # fill the cap
    r = NfqueueRunner(RuleEngine([Rule("h", parse_filter("TCP.dport == 80"), [Hold()])]),
                      intercept=iq)
    p = FakePkt(_ip())
    r.process(p)
    assert p.verdict == "drop"


def test_forward_queue_rules_scope_to_victims():
    install, remove = nft_forward_queue_rules(1, ["10.0.0.50", "10.0.0.51"])
    joined = " ".join(" ".join(c) for c in install)
    assert "saddr" in joined and "daddr" in joined
    assert "10.0.0.50" in joined and "queue num 1" in joined
    assert remove == [["nft", "delete", "table", "inet", "reforge_q"]]
    # no victims -> whole forward chain
    plain = " ".join(" ".join(c) for c in nft_forward_queue_rules(1)[0])
    assert "saddr" not in plain and "queue num 1" in plain


def test_nfqueue_seq_fixer_shifts_later_segments():
    from reforge.core.flowrewrite import FlowRewriter
    from reforge.rules.actions import PayloadReplace
    fx = FlowRewriter()
    r = NfqueueRunner(RuleEngine([Rule("g", parse_filter('Raw.load contains "HI"'),
                                       [PayloadReplace(b"HI", b"HELLO")])]),  # +3
                      seq_fixer=fx)
    # first segment grows -> fixer records the +3 delta for the flow
    p1 = FakePkt(bytes(IP(src="10.0.0.2", dst="10.0.0.1")
                       / TCP(sport=80, dport=5, flags="PA", seq=1000, ack=1) / b"HI-x"))
    r.process(p1)
    # a later segment (no rule match) must be shifted +3 by the fixer
    p2 = FakePkt(bytes(IP(src="10.0.0.2", dst="10.0.0.1")
                       / TCP(sport=80, dport=5, flags="PA", seq=1004, ack=1) / b"more"))
    r.process(p2)
    assert IP(p2.out)[TCP].seq == 1007
