"""Rule tracer: per-rule match/why-not/actions, drop short-circuit, formatting."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.diagnostics.tracer import format_trace, trace
from reforge.rules.actions import Drop, SetField
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter
from reforge.rules.matchers import AllMatch


def _frame(dport=80):
    return bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=dport) / b"x")


def test_trace_match_nomatch_disabled_and_reasons():
    rules = [
        Rule("off", AllMatch(), [], enabled=False),
        Rule("nomatch", parse_filter("TCP.dport == 22"), [SetField("IP", "dst", "1.1.1.1")]),
        Rule("hit", parse_filter("TCP.dport == 80"), [SetField("IP", "dst", "9.9.9.9")]),
    ]
    t = trace(RuleEngine(rules), _frame(80))
    by = {s.name: s for s in t.steps}
    assert by["off"].reason == "disabled"
    assert "not" in by["nomatch"].reason and "22" in by["nomatch"].reason
    assert by["hit"].matched is True and by["hit"].actions
    assert t.matched_rule == "hit" and t.modified is True
    assert t.disposition == "forward" and t.out_len


def test_trace_drop_stops_later_rules():
    rules = [
        Rule("drop", parse_filter("TCP.dport == 80"), [Drop()]),
        Rule("later", AllMatch(), [SetField("IP", "dst", "2.2.2.2")]),
    ]
    t = trace(RuleEngine(rules), _frame(80))
    by = {s.name: s for s in t.steps}
    assert t.disposition == "drop"
    assert by["later"].matched is False and "not evaluated" in by["later"].reason


def test_format_trace_is_readable():
    t = trace(RuleEngine([Rule("hit", AllMatch(), [SetField("IP", "dst", "9.9.9.9")])]),
              _frame())
    text = format_trace(t)
    assert "hit" in text and isinstance(text, str) and len(text) > 10
