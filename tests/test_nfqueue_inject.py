"""NFQUEUE inject/duplicate: extra sends now ride an injector, not dropped
(2026-09 review §2.2)."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP

from reforge.capture.nfqueue import NfqueueRunner
from reforge.rules.actions import Duplicate, SetField
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


def test_duplicate_action_injects_extra_packets():
    injected = []
    r = NfqueueRunner(
        RuleEngine([Rule("dup", parse_filter("TCP.dport == 80"), [Duplicate(2)])]),
        injector=injected.append,
    )
    p = FakePkt(_ip())
    r.process(p)
    assert p.verdict == "accept"
    assert len(injected) == 2 and r.stats.injected == 2      # both duplicates sent
    assert all(IP(b).dst == "10.0.0.9" for b in injected)


def test_no_extra_means_no_injection():
    injected = []
    r = NfqueueRunner(
        RuleEngine([Rule("rw", parse_filter("TCP.dport == 80"),
                         [SetField("IP", "dst", "10.0.0.99")])]),
        injector=injected.append,
    )
    r.process(FakePkt(_ip()))
    assert injected == [] and r.stats.injected == 0


def test_injector_failure_counts_error_not_crash():
    def boom(_raw):
        raise OSError("no raw socket")

    r = NfqueueRunner(
        RuleEngine([Rule("dup", parse_filter("TCP.dport == 80"), [Duplicate(1)])]),
        injector=boom,
    )
    p = FakePkt(_ip())
    r.process(p)                                             # must not raise
    assert p.verdict == "accept" and r.stats.injected == 0 and r.stats.errors == 1
