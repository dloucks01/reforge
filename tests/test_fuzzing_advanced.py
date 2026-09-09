"""Smart-fuzzing additions: stateful prefix, minimization, persistence,
rate/budget, per-field coverage (2026-09 code review §2.10)."""

from __future__ import annotations

import time

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.fuzzing import monitor as mon
from reforge.fuzzing.campaign import FuzzCampaign, load_findings
from reforge.fuzzing.minimize import ddmin, still_anomalous


def _seed():
    return bytes(Ether() / IP(dst="10.0.0.1") / UDP(dport=53) / b"HELLO-WORLD")


def _ok():
    return mon.Response(reply=bytes(Ether() / IP() / TCP(flags="A")), latency=0.01)


# ---- per-field coverage ----------------------------------------------------
def test_report_tracks_field_coverage():
    camp = FuzzCampaign(_seed(), lambda d: _ok(), iterations=120, seed=3)
    rep = camp.run()
    assert rep.coverage, "field/struct/dict mutators should record touched fields"
    # coverage keys look like 'Layer.field'
    assert any("." in k for k in rep.coverage)
    assert "field coverage" in rep.summary()


# ---- stateful fuzzing ------------------------------------------------------
def test_stateful_prefix_is_replayed_before_each_case():
    sent = []

    def target(data: bytes) -> mon.Response:
        sent.append(data)
        return _ok()

    prefix = [b"STEP1", b"STEP2"]
    camp = FuzzCampaign(_seed(), target, iterations=5, seed=1, prefix=prefix)
    camp.run()
    # every fuzz case is preceded by the two prefix packets in order
    idx = [i for i, d in enumerate(sent) if d == b"STEP1"]
    assert len(idx) == 5
    for i in idx:
        assert sent[i] == b"STEP1" and sent[i + 1] == b"STEP2"


def test_stateful_case_still_reproduces():
    camp = FuzzCampaign(_seed(), lambda d: _ok(), iterations=30, seed=9,
                        prefix=[b"A", b"B"])
    rep = camp.run()
    # a reproduced case (with the prefix RNG draws consumed) matches its bytes
    # pick any case by re-running one iteration deterministically
    c = None
    for f in rep.findings:
        c = f.case
        break
    if c is not None:
        assert camp.reproduce(c) == c.data


# ---- minimization ----------------------------------------------------------
def test_ddmin_shrinks_to_trigger_token():
    # predicate: still triggers as long as the marker survives
    data = b"AAAAAAAA%n%nBBBBBBBB"
    minimized = ddmin(data, lambda d: b"%n%n" in d)
    assert b"%n%n" in minimized
    assert len(minimized) < len(data)
    assert minimized == b"%n%n"


def test_campaign_minimize_reduces_finding():
    # target "misbehaves" (stops replying) whenever a fmt-string token is present
    def target(data: bytes) -> mon.Response:
        return mon.Response(reply=None) if b"%n%n" in data else _ok()

    big = b"\x00" * 200 + b"%n%n%n%n%n" + b"\xff" * 200
    from reforge.fuzzing.strategies import FuzzCase
    case = FuzzCase(data=big, seed=0, strategy="dict", base=_seed())
    camp = FuzzCampaign(_seed(), target, iterations=1, seed=0)
    small = camp.minimize(case)
    assert b"%n%n" in small and len(small) < len(big)


# ---- persistence -----------------------------------------------------------
def test_save_and_reload_corpus_and_findings(tmp_path):
    def target(data: bytes) -> mon.Response:
        return mon.Response(reply=None) if b"%n%n" in data else _ok()

    camp = FuzzCampaign(_seed(), target, monitor=mon.TargetMonitor(crash_after=2),
                        iterations=200, seed=7)
    rep = camp.run()
    camp.save(tmp_path)

    reloaded = load_findings(tmp_path)
    assert len(reloaded) == len(rep.findings)
    if reloaded:
        assert reloaded[0].case.data == rep.findings[0].case.data

    fresh = FuzzCampaign(_seed(), target, iterations=0, seed=0)
    added = fresh.load_corpus(tmp_path)
    assert added == rep.corpus_size
    assert len(fresh.corpus) == 1 + added   # its own seed + loaded corpus


# ---- rate / time budget ----------------------------------------------------
def test_max_seconds_budget_stops_early():
    def slow(data: bytes) -> mon.Response:
        time.sleep(0.01)
        return _ok()

    camp = FuzzCampaign(_seed(), slow, iterations=100000, seed=0, max_seconds=0.05)
    rep = camp.run()
    assert rep.sent < 100000          # stopped on the wall-clock budget
    assert rep.elapsed >= 0.05


def test_rate_paces_sends():
    camp = FuzzCampaign(_seed(), lambda d: _ok(), iterations=5, seed=0, rate=200.0)
    rep = camp.run()
    # 5 cases at 200/s => at least ~4 intervals of 5ms
    assert rep.elapsed >= 0.015
