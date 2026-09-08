"""rules.actions helpers/Plugin + engine ordering/dry-run/error handling."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.packet import Packet
from reforge.rules import actions as A
from reforge.rules.base import Disposition, Rule, Verdict
from reforge.rules.engine import RuleEngine
from reforge.rules.matchers import AllMatch


def _pkt(load=b"x", dport=80):
    return Packet.from_bytes(bytes(Ether() / IP() / TCP(dport=dport) / load))


def test_as_bytes_forms():
    assert A._as_bytes(b"raw") == b"raw"
    assert A._as_bytes("0xdead") == b"\xde\xad"
    assert A._as_bytes("de:ad:be:ef") == b"\xde\xad\xbe\xef"
    assert A._as_bytes("hello") == b"hello"


def test_set_field_coerces_str_to_int_and_skips_missing_layer():
    p = _pkt(dport=80)
    A.SetField("TCP", "dport", "0x1bb").apply(p, Verdict())     # str -> int
    assert p.scapy()[TCP].dport == 0x1bb
    p2 = _pkt()
    A.SetField("UDP", "dport", 53).apply(p2, Verdict())         # no UDP -> no-op
    assert not p2.modified


def test_plugin_action_runs_or_notes_missing():
    from reforge.plugins import PluginAPI
    PluginAPI().register_transform("setdport", lambda sc: sc[TCP].__setattr__("dport", 4444))
    p = _pkt(dport=80)
    v = Verdict()
    A.Plugin("setdport").apply(p, v)
    assert p.scapy()[TCP].dport == 4444
    v2 = Verdict()
    A.Plugin("nope-not-loaded").apply(_pkt(), v2)
    assert any("not loaded" in n for n in v2.notes)


def test_engine_dry_run_counts_but_does_not_modify():
    r = Rule("rw", AllMatch(), [A.SetField("IP", "dst", "9.9.9.9")])
    eng = RuleEngine([r], dry_run=True)
    v = eng.evaluate(_pkt())
    assert r.hits == 1 and v.matched_rule == "rw"
    assert any("dry-run" in n for n in v.notes)
    assert v.disposition is Disposition.FORWARD             # nothing actually applied


def test_engine_skips_disabled_and_short_circuits_on_drop():
    disabled = Rule("off", AllMatch(), [A.SetField("IP", "dst", "1.1.1.1")], enabled=False)
    drop = Rule("drop", AllMatch(), [A.Drop()])
    after = Rule("after", AllMatch(), [A.SetField("IP", "dst", "2.2.2.2")])
    eng = RuleEngine([disabled, drop, after])
    v = eng.evaluate(_pkt())
    assert v.disposition is Disposition.DROP
    assert disabled.hits == 0 and drop.hits == 1 and after.hits == 0   # stopped at drop


def test_engine_swallows_match_and_action_errors():
    class BoomMatch(AllMatch):
        def matches(self, pkt):
            raise RuntimeError("bad match")

    class BoomAction(A.Action):
        def apply(self, pkt, verdict):
            raise RuntimeError("bad action")

    eng = RuleEngine([Rule("m", BoomMatch(), []),
                      Rule("a", AllMatch(), [BoomAction()])])
    v = eng.evaluate(_pkt())                                 # must not raise
    assert v.matched_rule == "a"
