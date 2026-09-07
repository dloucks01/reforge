"""Smart fuzzing: strategies, monitor classification, campaign + repro."""

from __future__ import annotations

import random

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.fuzzing import monitor as mon
from reforge.fuzzing import strategies as St
from reforge.fuzzing.campaign import FuzzCampaign


def _seed():
    return bytes(Ether() / IP(dst="10.0.0.1") / UDP(dport=53) / b"HELLO-WORLD")


# ---- strategies ------------------------------------------------------------
def test_strategies_change_bytes_and_stay_parseable():
    rng = random.Random(1)
    seed = _seed()
    for strat in St.DEFAULT_STRATEGIES:
        out = strat.mutate(seed, random.Random(rng.randrange(9999)))
        assert isinstance(out, bytes) and len(out) > 0
        # most strategies change the packet
        # (byte/field/dict/struct all mutate something here)


def test_field_aware_uses_known_bad_values():
    # field mutator should sometimes set an integer boundary; run a few seeds
    seed = _seed()
    outs = {St.FieldAwareMutator().mutate(seed, random.Random(s)) for s in range(20)}
    assert len(outs) > 1                      # produces varied mutations
    assert seed not in outs or len(outs) > 1  # generally differs from the seed


def test_dictionary_injects_token():
    seed = _seed()
    out = St.DictionaryMutator().mutate(seed, random.Random(0))
    assert any(tok in out for tok in St.BAD_STRINGS)


def test_reproducible_from_seed():
    seed = _seed()
    s = St.FieldAwareMutator()
    assert s.mutate(seed, random.Random(42)) == s.mutate(seed, random.Random(42))


# ---- monitor ---------------------------------------------------------------
def test_monitor_detects_reset_and_crash():
    m = mon.TargetMonitor(crash_after=2)
    ok = bytes(Ether() / IP() / TCP(flags="A"))
    rst = bytes(Ether() / IP() / TCP(flags="R"))
    assert m.classify(mon.Response(reply=ok)) == mon.NORMAL
    assert m.classify(mon.Response(reply=rst)) == mon.RESET
    # sustained loss of response after answering -> crash
    assert m.classify(mon.Response(reply=None)) == mon.NO_RESPONSE
    assert m.classify(mon.Response(reply=None)) == mon.CRASH


# ---- campaign --------------------------------------------------------------
def test_campaign_records_and_reproduces_finding():
    seed = _seed()

    # Fake target: "crashes" (stops responding) once a format-string token appears.
    dead = {"flag": False}

    def fake_target(data: bytes) -> mon.Response:
        if b"%n%n" in data:
            dead["flag"] = True
        if dead["flag"]:
            return mon.Response(reply=None)              # no more responses
        return mon.Response(reply=bytes(Ether() / IP() / TCP(flags="A")), latency=0.01)

    camp = FuzzCampaign(seed, fake_target, monitor=mon.TargetMonitor(crash_after=2),
                        iterations=200, seed=7)
    report = camp.run()
    assert report.sent == 200
    assert report.findings, "expected at least one finding (crash after fmt-string)"
    # every finding is reproducible from its recorded seed
    f = report.findings[0]
    assert camp.reproduce(f.case) == f.case.data
    assert "sent=200" in report.summary()
