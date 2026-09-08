"""Bridge internals: the threaded loop (via a pipe-backed fake port) and the
_forward branches not hit elsewhere (unarmed, engine error, delay, hold without
a queue, egress-drop, injection, and park overflow)."""

from __future__ import annotations

import os
import time
from collections import deque

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.core.intercept import InterceptQueue
from reforge.rules.actions import Delay, Drop, Duplicate, Hold
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter


def _frame(load=b"x", dport=9999):
    return bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
                 / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=dport) / load)


# ---- a real-fd fake port so select() in the loop works offline ------------
class FakePort:
    def __init__(self, iface):
        self.iface = iface
        self._r, self._w = os.pipe()
        self._frames: deque = deque()
        self.sent: list = []
        self.closed = False

    def feed(self, data: bytes) -> None:
        self._frames.append(data)
        os.write(self._w, b"\x01")               # make the fd readable

    def fileno(self) -> int:
        return self._r

    def recv(self):
        try:
            os.read(self._r, 1)
        except OSError:
            pass
        return self._frames.popleft() if self._frames else None

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def close(self) -> None:
        self.closed = True
        for fd in (self._r, self._w):
            try:
                os.close(fd)
            except OSError:
                pass


def _wait(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.01)
    return False


def test_threaded_loop_forwards_both_directions_and_suppresses_echo():
    ports: dict = {}

    def factory(iface):
        p = FakePort(iface)
        ports[iface] = p
        return p

    br = UserspaceBridge("ethA", "ethB", RuleEngine([]), port_factory=factory)
    br.start()
    try:
        assert br.wait_ready(timeout=3.0)
        pa, pb = ports["ethA"], ports["ethB"]

        f1 = _frame(b"a2b")
        pa.feed(f1)
        assert _wait(lambda: pb.sent)                    # forwarded A->B
        assert pb.sent[0] == f1
        assert br.counters.a_to_b == 1 and br.counters.forwarded == 1

        f2 = _frame(b"b2a")
        pb.feed(f2)
        assert _wait(lambda: pa.sent)
        assert br.counters.b_to_a == 1

        # echo suppression: the exact bytes we just transmitted on B, seen back
        # on B's ingress, must NOT be forwarded to A again
        before = len(pa.sent)
        pb.feed(f1)                                      # f1 was just sent on B
        time.sleep(0.3)
        assert len(pa.sent) == before                    # echo swallowed

        assert br.heartbeat_age() < 2.0
        assert br.drain()                                # tapped frames available
    finally:
        br.stop()
    assert br.running is False
    assert ports["ethA"].closed and ports["ethB"].closed


def test_loop_fails_when_ports_cannot_open():
    def boom(iface):
        raise OSError("no such device")

    br = UserspaceBridge("ethA", "ethB", port_factory=boom)
    br.start()
    assert br.wait_ready(timeout=1.0) is False           # never became ready
    assert br.running is False


# ---- _forward branches ----------------------------------------------------
def test_unarmed_is_pure_passthrough():
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("d", parse_filter("TCP.dport == 9999"), [Drop()])]),
                         armed=False)
    out = br.process_frame("ethA", _frame())             # would DROP if armed
    assert out == [_frame()]                             # but unarmed => passes through
    assert br.counters.forwarded == 1 and br.counters.dropped == 0


class _BoomEngine:
    def evaluate(self, pkt):
        raise RuntimeError("engine blew up")


def test_engine_error_forwards_original_and_counts():
    br = UserspaceBridge("ethA", "ethB", _BoomEngine())
    out = br.process_frame("ethA", _frame())
    assert out == [_frame()]                             # original forwarded
    assert br.counters.errors == 1 and br.counters.forwarded == 1


def test_delay_action_still_forwards():
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("slow", parse_filter("TCP.dport == 9999"),
                                          [Delay(0.001)])]))
    t0 = time.monotonic()
    out = br.process_frame("ethA", _frame())
    assert out == [_frame()] and time.monotonic() - t0 >= 0.001


def test_hold_without_queue_passes_through():
    # process_frame nulls the intercept queue -> HOLD falls through to forward
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("h", parse_filter("TCP.dport == 9999"), [Hold()])]),
                         intercept=InterceptQueue())
    out = br.process_frame("ethA", _frame())
    assert out == [_frame()] and br.counters.held == 1


# ---- intercept egress: drop + injection -----------------------------------
def test_held_packet_resolved_drop_counts_dropped():
    iq = InterceptQueue()
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("h", parse_filter("TCP.dport == 9999"), [Hold()])]),
                         intercept=iq, armed=True)
    br._forward("ethA", _frame(), lambda d: None)        # held
    hp = iq.pending()[0]
    iq.resolve(hp.id, "drop")                             # egress_release(None)
    assert br.counters.dropped == 1


def test_injection_released_behind_a_held_head():
    iq = InterceptQueue()
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("dup", parse_filter('Raw.load contains "GO"'),
                                          [Duplicate(1)])]),
                         intercept=iq, armed=True)
    egress: list = []
    same_flow = _frame(b"GO")
    # hold a head packet on this flow so later forwards queue behind it
    iq.hold("ethA", _frame(b"HEAD"), lambda o: egress.append(("HEAD", o)),
            flow_key=br._flow_key("ethA", same_flow))
    br._forward("ethA", same_flow, lambda d: egress.append(("main", d)))  # dup injected
    # release the head -> everything behind it flushes, including the injected dup
    for hp in list(iq.pending()):
        iq.resolve(hp.id, "forward")
    assert br.counters.injected >= 1


# ---- park overflow --------------------------------------------------------
def test_park_overflow_drop_at_capacity():
    iq = InterceptQueue(max_held=1, overflow="drop")
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("h", parse_filter("TCP.dport == 9999"), [Hold()])]),
                         intercept=iq, armed=True)
    iq.hold("ethA", b"filler", lambda o: None, flow_key=("z", 1))   # fill capacity
    br._forward("ethA", _frame(), lambda d: None)        # can't hold -> overflow drop
    assert br.counters.dropped == 1


def test_park_overflow_forward_at_capacity():
    iq = InterceptQueue(max_held=1, overflow="forward")
    br = UserspaceBridge("ethA", "ethB",
                         RuleEngine([Rule("h", parse_filter("TCP.dport == 9999"), [Hold()])]),
                         intercept=iq, armed=True)
    iq.hold("ethA", b"filler", lambda o: None, flow_key=("z", 1))   # fill capacity
    sent: list = []
    br._forward("ethA", _frame(), sent.append)           # overflow -> forward
    assert sent == [_frame()] and br.counters.forwarded == 1


def test_flow_rewrite_selects_position_aware_fixer():
    from reforge.core.flowrewrite import FlowRewriter
    br = UserspaceBridge("ethA", "ethB", flow_rewrite=True)
    assert isinstance(br.seq_fixer, FlowRewriter)
    assert br.seq_fixup is True
    br.set_seq_fixup(False)                              # disabling clears it
    assert br.seq_fixup is False
