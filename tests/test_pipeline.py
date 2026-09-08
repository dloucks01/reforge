"""Pipeline.process_one dispositions + the run loop over a synthetic backend."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.capture.base import Frame
from reforge.core.pipeline import Pipeline
from reforge.rules.actions import Drop, Duplicate, Hold, SetField
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter


def _frame(dport=80):
    return Frame(data=bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=dport) / b"x"),
                 ingress="ethA")


def test_process_one_forward_modify_drop_hold_inject():
    fwd = Pipeline(None, RuleEngine([]))
    assert len(fwd.process_one(_frame())) == 1 and fwd.counters.forwarded == 1

    mod = Pipeline(None, RuleEngine([Rule("m", parse_filter("TCP.dport == 80"),
                                          [SetField("IP", "dst", "9.9.9.9")])]))
    out = mod.process_one(_frame())
    assert Ether(out[0].data)[IP].dst == "9.9.9.9" and mod.counters.modified == 1

    drop = Pipeline(None, RuleEngine([Rule("d", parse_filter("TCP.dport == 80"), [Drop()])]))
    assert drop.process_one(_frame()) == [] and drop.counters.dropped == 1

    hold = Pipeline(None, RuleEngine([Rule("h", parse_filter("TCP.dport == 80"), [Hold()])]))
    assert hold.process_one(_frame()) == [] and hold.counters.held == 1

    dup = Pipeline(None, RuleEngine([Rule("x", parse_filter("TCP.dport == 80"),
                                          [Duplicate(2)])]))
    out = dup.process_one(_frame())
    assert len(out) == 3 and dup.counters.injected == 2


def test_run_loop_over_synthetic_backend():
    from reforge.testlab.synthetic import SyntheticBackend

    pipe = Pipeline(SyntheticBackend(speed=1000.0), RuleEngine([]))
    pipe.run(max_iterations=3)
    assert pipe.counters.captured >= 1
    assert pipe.counters.forwarded >= 1
