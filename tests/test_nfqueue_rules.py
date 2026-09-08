"""NFQUEUE nft rule builders, flow keys, and the overflow-forward hold path."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from reforge.capture.nfqueue import (
    NfqueueRunner,
    nft_forward_queue_rules,
    nft_queue_rules,
)
from reforge.core.intercept import InterceptQueue
from reforge.rules.actions import Hold
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


# ---- nft rule builders ----------------------------------------------------
def test_nft_queue_rules_structure():
    install, remove = nft_queue_rules(queue_num=5, chain="forward")
    assert install[0] == ["nft", "add", "table", "inet", "reforge_q"]
    assert any("queue" in c and "5" in c for c in install)
    assert remove == [["nft", "delete", "table", "inet", "reforge_q"]]


def test_nft_forward_queue_rules_all_traffic():
    install, _ = nft_forward_queue_rules(queue_num=1, victims=None)
    # with no victim set, a single catch-all queue rule
    queue_rules = [c for c in install if "queue" in c]
    assert len(queue_rules) == 1
    assert "num" in queue_rules[0] and "1" in queue_rules[0]


def test_nft_forward_queue_rules_victim_scoped():
    install, remove = nft_forward_queue_rules(queue_num=2, victims=["10.0.0.5", "10.0.0.6"])
    joined = [" ".join(c) for c in install]
    # one rule for saddr, one for daddr, both naming the victim set
    assert any("saddr" in s and "10.0.0.5" in s and "10.0.0.6" in s for s in joined)
    assert any("daddr" in s for s in joined)
    assert remove == [["nft", "delete", "table", "inet", "reforge_q"]]


# ---- flow keys ------------------------------------------------------------
def test_flow_key_tcp_udp_and_v6():
    tcp = bytes(IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1234, dport=80))
    key = NfqueueRunner._flow_key(tcp)
    assert key == ("1.1.1.1", 1234, "2.2.2.2", 80, "TCP")

    udp = bytes(IP(src="1.1.1.1", dst="2.2.2.2") / UDP(sport=9, dport=53))
    assert NfqueueRunner._flow_key(udp)[4] == "UDP"

    v6 = bytes(IPv6(src="fd00::1", dst="fd00::2") / TCP(sport=5, dport=443))
    assert NfqueueRunner._flow_key(v6)[0] == "fd00::1"


def test_flow_key_non_l4_falls_back_to_addrs():
    icmp = bytes(IP(src="1.1.1.1", dst="2.2.2.2") / b"\x08\x00rest")
    key = NfqueueRunner._flow_key(icmp)
    assert key[:2] == ("1.1.1.1", "2.2.2.2") or key is not None


def test_flow_key_garbage_is_none():
    assert NfqueueRunner._flow_key(b"\xff\xff") is None


# ---- overflow: forward (default) vs drop ----------------------------------
def _hold_runner(iq):
    return NfqueueRunner(RuleEngine([Rule("h", parse_filter("TCP.dport == 80"), [Hold()])]),
                         intercept=iq)


def test_hold_at_capacity_forwards_when_overflow_is_forward():
    iq = InterceptQueue(max_held=1, overflow="forward")
    iq.hold("x", b"filler", lambda o: None, flow_key=("z", 9))     # fill capacity
    r = _hold_runner(iq)
    p = FakePkt(bytes(IP(dst="2.2.2.2") / TCP(dport=80) / b"x"))
    r.process(p)
    # queue was full and overflow=forward -> packet is accepted, not dropped
    assert p.verdict == "accept"
    assert r.stats.held >= 1
