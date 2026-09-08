"""rules.spec: build Rule/Match/Action from dict specs, and human summaries."""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.core.apply import apply_engine
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules import spec as S
from reforge.rules.base import Disposition
from reforge.rules.engine import RuleEngine


# ---- build_match ----------------------------------------------------------
def test_build_match_all_layer_field():
    assert isinstance(S.build_match({"type": "all"}), M.AllMatch)
    assert isinstance(S.build_match({"type": "layer", "layer": "TCP"}), M.LayerMatch)
    fm = S.build_match({"type": "field", "layer": "UDP", "field": "dport",
                        "op": "eq", "value": 53})
    assert isinstance(fm, M.FieldMatch)


def test_build_match_boolean_combinators():
    spec = {"type": "and", "of": [
        {"type": "layer", "layer": "IP"},
        {"type": "or", "of": [
            {"type": "field", "layer": "TCP", "field": "dport", "op": "eq", "value": 80},
            {"type": "not", "inner": {"type": "all"}},
        ]},
    ]}
    m = S.build_match(spec)
    assert isinstance(m, M.AndMatch)
    from reforge.core.packet import Packet
    pkt = Packet.from_bytes(bytes(Ether() / IP() / TCP(dport=80)))
    assert m.matches(pkt)


def test_build_match_unknown_raises():
    with pytest.raises(ValueError, match="unknown match type"):
        S.build_match({"type": "bogus"})


# ---- build_action ---------------------------------------------------------
def test_build_action_core_types():
    assert isinstance(S.build_action({"type": "drop"}), A.Drop)
    assert isinstance(S.build_action({"type": "hold"}), A.Hold)
    assert isinstance(S.build_action({"type": "delay", "seconds": 0.1}), A.Delay)
    assert isinstance(S.build_action({"type": "duplicate", "times": 3}), A.Duplicate)
    sf = S.build_action({"type": "set_field", "layer": "IP", "field": "dst", "value": "1.2.3.4"})
    assert isinstance(sf, A.SetField)
    pr = S.build_action({"type": "payload_replace", "find": "a", "replace": "b"})
    assert isinstance(pr, A.PayloadReplace)


def test_build_action_lazy_imported_types():
    assert S.build_action({"type": "fuzz", "mutations": 2, "seed": 1}) is not None
    assert S.build_action({"type": "plugin", "name": "p"}) is not None
    assert S.build_action({"type": "strip_starttls"}) is not None
    for t in ("http_sslstrip", "http_strip_encoding", "http_inject",
              "http_replace_body", "http_strip_cookie", "http_remove_sec_headers"):
        assert S.build_action({"type": t}) is not None


def test_build_action_unknown_raises():
    with pytest.raises(ValueError, match="unknown action type"):
        S.build_action({"type": "nope"})


# ---- build_rule(s) + end-to-end through the engine ------------------------
def test_build_rule_defaults_and_enabled_flag():
    r = S.build_rule({"actions": [{"type": "drop"}]})
    assert r.name == "rule" and r.enabled is True
    assert isinstance(r.match, M.AllMatch)
    r2 = S.build_rule({"name": "x", "enabled": False, "match": {"type": "all"},
                       "actions": []})
    assert r2.name == "x" and r2.enabled is False


def test_spec_built_rule_applies_in_engine():
    rules = S.build_rules([{
        "name": "rw", "match": {"type": "field", "layer": "TCP", "field": "dport",
                                "op": "eq", "value": 80},
        "actions": [{"type": "set_field", "layer": "IP", "field": "dst", "value": "10.9.9.9"}],
    }])
    eng = RuleEngine(rules)
    res = apply_engine(eng, bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=80) / b"x"))
    assert res.modified and Ether(res.out)[IP].dst == "10.9.9.9"


def test_drop_spec_disposition():
    eng = RuleEngine(S.build_rules([{"match": {"type": "all"}, "actions": [{"type": "drop"}]}]))
    res = apply_engine(eng, bytes(Ether() / IP() / UDP()))
    assert res.disposition is Disposition.DROP


# ---- summaries ------------------------------------------------------------
def test_match_summaries():
    assert S.match_summary({"type": "all"}) == "any packet"
    assert S.match_summary({"type": "layer", "layer": "TCP"}) == "has TCP"
    assert "UDP.dport eq 53" in S.match_summary(
        {"type": "field", "layer": "UDP", "field": "dport", "op": "eq", "value": 53})
    assert " and " in S.match_summary({"type": "and", "of": [
        {"type": "layer", "layer": "IP"}, {"type": "layer", "layer": "TCP"}]})
    assert S.match_summary({"type": "not", "inner": {"type": "all"}}).startswith("not (")


def test_action_summaries():
    assert "set IP.dst=" in S.action_summary(
        {"type": "set_field", "layer": "IP", "field": "dst", "value": "1.1.1.1"})
    assert S.action_summary({"type": "delay", "seconds": 0.2}) == "delay 0.2s"
    assert S.action_summary({"type": "duplicate", "times": 2}) == "duplicate x2"
    assert S.action_summary({"type": "fuzz", "mutations": 3}) == "fuzz x3"
    assert S.action_summary({"type": "http_sslstrip"}) == "http:sslstrip"
    assert S.action_summary({"type": "http_replace_body"}) == "http:replace-body"
    assert "http:inject" in S.action_summary({"type": "http_inject", "snippet": "<script>"})
