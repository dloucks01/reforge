"""Phase 3: userspace bridge forwarding/manipulation, watchdog, netconfig."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.core.watchdog import Watchdog
from reforge.privhelper.netconfig import (
    RevertJournal,
    fail_open_commands,
    prepare_bridge,
)
from reforge.rules import actions as A
from reforge.rules import matchers as M
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


def _frame(dst_mac="11:22:33:44:55:66", dport=80):
    return bytes(Ether(src="aa:aa:aa:aa:aa:aa", dst=dst_mac)
                 / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(dport=dport) / b"hi")


# ---- bridge forwarding -----------------------------------------------------
def test_passthrough_forwards_both_directions():
    br = UserspaceBridge("ethA", "ethB")
    assert br.process_frame("ethA", _frame()) == [_frame()]
    assert br.process_frame("ethB", _frame()) == [_frame()]
    assert br.counters.captured == 2
    assert br.counters.a_to_b == 1
    assert br.counters.b_to_a == 1
    # both frames were tapped for the GUI
    assert len(br.drain()) == 2


def test_drop_rule_blocks():
    engine = RuleEngine([Rule("drop80", M.FieldMatch("TCP", "dport", "eq", 80), [A.Drop()])])
    br = UserspaceBridge("ethA", "ethB", engine)
    assert br.process_frame("ethA", _frame(dport=80)) == []
    assert br.counters.dropped == 1
    assert br.counters.forwarded == 0


def test_l2_rewrite():
    engine = RuleEngine([Rule("mac", M.AllMatch(),
                              [A.SetField("Ether", "dst", "de:ad:be:ef:00:01")])])
    br = UserspaceBridge("ethA", "ethB", engine)
    out = br.process_frame("ethA", _frame())
    assert len(out) == 1
    assert Ether(out[0]).dst == "de:ad:be:ef:00:01"
    assert br.counters.modified == 1


def test_duplicate_injects():
    engine = RuleEngine([Rule("dup", M.AllMatch(), [A.Duplicate(2)])])
    br = UserspaceBridge("ethA", "ethB", engine)
    out = br.process_frame("ethA", _frame())
    assert len(out) == 3            # original + 2 duplicates
    assert br.counters.injected == 2
    assert br.counters.forwarded == 3


def test_tap_can_be_disabled():
    br = UserspaceBridge("ethA", "ethB", tap=False)
    br.process_frame("ethA", _frame())
    assert br.drain() == []


def test_echo_suppression_breaks_loops():
    # A frame we just transmitted must be recognized as our own echo once,
    # so the forward loop won't re-forward it (which would storm the wire).
    br = UserspaceBridge("ethA", "ethB")
    data = _frame()
    br._remember_sent(data)
    assert br._is_own_echo(data)       # first re-capture: suppressed
    assert not br._is_own_echo(data)   # consumed; a later real copy passes


# ---- watchdog --------------------------------------------------------------
def test_watchdog_should_trip():
    wd = Watchdog(heartbeat_age=lambda: 0.0, timeout=1.0, on_trip=lambda: None)
    assert wd.should_trip(age=2.0)
    assert not wd.should_trip(age=0.5)


def test_watchdog_trips_once():
    calls = []
    wd = Watchdog(heartbeat_age=lambda: 5.0, timeout=1.0, on_trip=lambda: calls.append(1))
    wd._check_once()
    wd._check_once()
    assert calls == [1]           # only fires once
    assert wd.tripped


# ---- netconfig revert journal ----------------------------------------------
def test_prepare_bridge_records_reverts():
    journal = RevertJournal()
    planned = prepare_bridge("ethA", "ethB", journal, apply=False)  # plan only, no exec
    assert any("promisc" in " ".join(c) for c in planned)
    assert journal.entries                     # undo steps recorded

    ran: list[list[str]] = []
    journal.revert(ran.append)
    assert ran                                 # revert executed the undo steps
    # revert runs in reverse order of recording
    assert not journal.entries                 # journal cleared after revert


def test_fail_open_builds_kernel_bridge():
    journal = RevertJournal()
    planned = fail_open_commands("ethA", "ethB", journal, apply=False)
    joined = [" ".join(c) for c in planned]
    assert any("type bridge" in j for j in joined)
    assert any("master" in j for j in joined)
    # teardown deletes the fallback bridge
    ran: list[list[str]] = []
    journal.revert(ran.append)
    assert any("del" in " ".join(c) for c in ran)
