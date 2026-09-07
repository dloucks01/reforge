"""Phase 6: tracer, self-test, health, knowledge base, diagnostic bundle."""

from __future__ import annotations

import json

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.diagnostics import bundle, health, kb, selftest, tracer
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _engine():
    return RuleEngine([
        Rule("drop-80", M.FieldMatch("TCP", "dport", "eq", 80), [A.Drop()]),
        Rule("rewrite", M.FieldMatch("UDP", "dport", "eq", 53),
             [A.SetField("IP", "dst", "10.0.0.9")]),
    ])


# ---- tracer ----------------------------------------------------------------
def test_trace_drop_path():
    raw = bytes(Ether() / IP(dst="1.1.1.1") / TCP(dport=80))
    t = tracer.trace(_engine(), raw)
    assert t.disposition == "drop"
    assert t.matched_rule == "drop-80"
    first = t.steps[0]
    assert first.matched and "drop" in " ".join(first.actions)
    # second rule is recorded as not-evaluated because the packet was dropped
    assert not t.steps[1].matched
    assert "not evaluated" in t.steps[1].reason


def test_trace_explains_non_match():
    raw = bytes(Ether() / IP(dst="1.1.1.1") / TCP(dport=443))
    t = tracer.trace(_engine(), raw)
    assert t.disposition == "forward"
    assert t.matched_rule is None
    # drop-80 didn't match: reason shows actual vs wanted
    assert "dport=443" in t.steps[0].reason and "80" in t.steps[0].reason


def test_trace_forward_modified():
    raw = bytes(Ether() / IP(dst="8.8.8.8") / UDP(dport=53) / b"q")
    t = tracer.trace(_engine(), raw)
    assert t.disposition == "forward"
    assert t.matched_rule == "rewrite"
    assert t.modified and t.out_len and t.out_len > 0
    assert "IP.dst" in tracer.format_trace(t)


# ---- self-test -------------------------------------------------------------
def test_pipeline_selftest_passes():
    report = selftest.run_selftest()
    assert report.ok
    assert all(s.ok for s in report.steps)
    assert any("checksum" in s.name for s in report.steps)
    # the self-test also exercises the intercept and HTTP-message paths
    names = [s.name for s in report.steps]
    assert "intercept holds a match" in names
    assert "intercept edit forwards" in names
    assert "HTTP body rewrite" in names


# ---- health ----------------------------------------------------------------
def test_rate_meter_computes_rates():
    m = health.RateMeter()
    assert m.update({"captured": 0}, now=0.0) == {}          # first sample: no rate
    rates = m.update({"captured": 100}, now=1.0)
    assert rates["captured_per_s"] == 100.0


def test_snapshot_without_service():
    snap = health.snapshot(None)
    assert snap["running"] is False
    assert "system" in snap


# ---- knowledge base --------------------------------------------------------
def test_kb_search():
    assert any(e.id == "offloads" for e in kb.search("offload"))
    assert kb.search("") == kb.ENTRIES         # empty query returns all
    assert kb.search("zzznomatch") == []


# ---- diagnostic bundle -----------------------------------------------------
def test_bundle_collect_and_write(tmp_path):
    data = bundle.collect(interfaces=[], counters={"captured": 5}, rules=[{"name": "r"}])
    assert data["tool"] == "reforge" and "doctor" in data
    assert data["counters"] == {"captured": 5}

    path = bundle.write_bundle(tmp_path / "diag.json", counters={"x": 1})
    parsed = json.loads(path.read_text())
    assert parsed["version"] == data["version"]
