"""Phase 2: matchers, actions, checksum recompute, apply, NFQUEUE, specs."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.core.apply import apply_engine
from reforge.core.packet import Packet
from reforge.rules.base import Disposition, Rule
from reforge.rules.engine import RuleEngine
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules import spec as S


def _frame(dst="10.0.0.1", dport=80, payload=b"GET / HTTP/1.1\r\n"):
    return bytes(Ether() / IP(src="10.0.0.5", dst=dst) / TCP(sport=1111, dport=dport) / payload)


def _ip_checksum_ok(raw: bytes, link="ether") -> bool:
    """True if the IP checksum stored in raw matches a fresh recomputation."""
    base = Ether if link == "ether" else IP
    pkt = base(raw)
    stored = pkt[IP].chksum
    del pkt[IP].chksum
    recomputed = base(bytes(pkt))[IP].chksum
    return stored == recomputed


# ---- matchers --------------------------------------------------------------
def test_field_match_eq():
    pkt = Packet.from_bytes(_frame(dport=80))
    assert M.FieldMatch("TCP", "dport", "eq", 80).matches(pkt)
    assert not M.FieldMatch("TCP", "dport", "eq", 443).matches(pkt)


def test_field_match_cidr():
    pkt = Packet.from_bytes(_frame())
    assert M.FieldMatch("IP", "src", "cidr", "10.0.0.0/24").matches(pkt)
    assert not M.FieldMatch("IP", "src", "cidr", "192.168.0.0/16").matches(pkt)


def test_and_or_not():
    pkt = Packet.from_bytes(_frame(dport=80))
    m = M.AndMatch([M.LayerMatch("TCP"), M.FieldMatch("TCP", "dport", "eq", 80)])
    assert m.matches(pkt)
    assert M.NotMatch(M.FieldMatch("TCP", "dport", "eq", 443)).matches(pkt)


# ---- actions + checksum recompute -----------------------------------------
def test_set_field_recomputes_checksum():
    engine = RuleEngine([Rule("r", M.AllMatch(), [A.SetField("IP", "dst", "10.9.9.9")])])
    res = apply_engine(engine, _frame(dst="10.0.0.1"))
    assert res.modified
    assert Ether(res.out)[IP].dst == "10.9.9.9"
    assert _ip_checksum_ok(res.out)  # checksum was recomputed correctly


def test_payload_replace_updates_length_and_checksum():
    engine = RuleEngine([Rule("r", M.AllMatch(),
                              [A.PayloadReplace(b"GET", b"POSTX")])])  # grows payload
    res = apply_engine(engine, _frame())
    out = Ether(res.out)
    assert b"POSTX" in bytes(out[TCP].payload)
    assert out[IP].len == len(bytes(out[IP]))  # length field consistent
    assert _ip_checksum_ok(res.out)


def test_drop():
    engine = RuleEngine([Rule("r", M.FieldMatch("TCP", "dport", "eq", 80), [A.Drop()])])
    res = apply_engine(engine, _frame(dport=80))
    assert res.disposition is Disposition.DROP
    assert res.out is None


def test_delay_and_duplicate():
    engine = RuleEngine([Rule("r", M.AllMatch(), [A.Delay(0.2), A.Duplicate(2)])])
    res = apply_engine(engine, _frame())
    assert res.delay_s == 0.2
    assert len(res.extra) == 2


def test_dry_run_does_not_modify():
    engine = RuleEngine([Rule("r", M.AllMatch(), [A.SetField("IP", "dst", "1.2.3.4")])],
                        dry_run=True)
    original = _frame(dst="10.0.0.1")
    res = apply_engine(engine, original)
    assert res.out == original          # unchanged
    assert engine.rules[0].hits == 1    # but the match was counted


# ---- NFQUEUE (IP-layer) path ----------------------------------------------
class _FakeNfqPacket:
    def __init__(self, payload: bytes):
        self._payload = payload
        self.verdict = None
        self.new_payload = None

    def get_payload(self):
        return self._payload

    def set_payload(self, data):
        self.new_payload = data

    def accept(self):
        self.verdict = "accept"

    def drop(self):
        self.verdict = "drop"


def test_nfqueue_process_modifies_and_accepts():
    from reforge.capture.nfqueue import NfqueueRunner

    engine = RuleEngine([Rule("r", M.AllMatch(), [A.SetField("IP", "dst", "10.9.9.9")])])
    runner = NfqueueRunner(engine)
    ip_payload = bytes(IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=80) / b"hi")
    p = _FakeNfqPacket(ip_payload)
    runner.process(p)
    assert p.verdict == "accept"
    assert p.new_payload is not None
    assert IP(p.new_payload).dst == "10.9.9.9"
    assert runner.stats.modified == 1
    assert _ip_checksum_ok(p.new_payload, link="ip")


def test_nfqueue_process_drops():
    from reforge.capture.nfqueue import NfqueueRunner

    engine = RuleEngine([Rule("r", M.FieldMatch("TCP", "dport", "eq", 80), [A.Drop()])])
    runner = NfqueueRunner(engine)
    p = _FakeNfqPacket(bytes(IP(dst="10.0.0.1") / TCP(dport=80)))
    runner.process(p)
    assert p.verdict == "drop"
    assert runner.stats.dropped == 1


# ---- spec factory ----------------------------------------------------------
def test_build_rule_from_spec_and_summaries():
    spec = {
        "name": "redirect",
        "match": {"type": "field", "layer": "UDP", "field": "dport", "op": "eq", "value": 53},
        "actions": [{"type": "set_field", "layer": "IP", "field": "dst", "value": "10.0.0.9"}],
    }
    rule = S.build_rule(spec)
    assert rule.name == "redirect"
    engine = RuleEngine([rule])
    dns = bytes(Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / b"q")
    res = apply_engine(engine, dns)
    assert Ether(res.out)[IP].dst == "10.0.0.9"
    assert "UDP.dport eq 53" in S.match_summary(spec["match"])
    assert "set IP.dst" in S.action_summary(spec["actions"][0])
