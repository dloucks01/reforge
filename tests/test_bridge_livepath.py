"""Live-path hardening: delay keeps the watchdog fed, and transmit/_sent are
serialized across threads (2026-09 review §3.6, §3.7)."""

from __future__ import annotations

import threading
import time

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.core.bridge import UserspaceBridge
from reforge.rules.actions import Delay
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter


def _frame(dport=80, load=b"x"):
    return bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=dport) / load)


class _CollectPort:
    """Fake port: records sends; recv() blocks so the loop just idles."""
    def __init__(self, iface):
        self.iface = iface
        self.sent = []
        self._ev = threading.Event()

    def fileno(self):
        return -1

    def recv(self):
        self._ev.wait(0.05)
        return None

    def send(self, data):
        self.sent.append(data)

    def close(self):
        pass


def test_delay_refreshes_heartbeat_and_does_not_stall_watchdog():
    br = UserspaceBridge("a", "b",
                         RuleEngine([Rule("d", parse_filter("TCP.dport == 80"), [Delay(0.6)])]))
    br._running.set()                       # simulate the running loop for _sleep_delay
    br._heartbeat = time.monotonic()

    done = threading.Event()

    def drive():
        br._forward("a", _frame(), lambda d: None)   # will delay 0.6s in chunks
        done.set()

    t = threading.Thread(target=drive, daemon=True)
    t.start()
    # during the delay the heartbeat must stay young (chunked refresh < 0.2s)
    time.sleep(0.35)
    assert br.heartbeat_age() < 0.25, "watchdog would trip: heartbeat not refreshed"
    done.wait(2.0)
    br._running.clear()


def test_headless_delay_does_not_sleep():
    br = UserspaceBridge("a", "b",
                         RuleEngine([Rule("d", parse_filter("TCP.dport == 80"), [Delay(5.0)])]))
    t = time.monotonic()
    br.process_frame("a", _frame())          # loop not running -> no sleep
    assert time.monotonic() - t < 0.5


def test_concurrent_emit_is_serialized():
    # two threads emitting through the same bridge must not interleave a send
    br = UserspaceBridge("a", "b")
    sends = []
    inside = {"n": 0}
    lock_ok = {"race": False}

    def fake_send(data):
        inside["n"] += 1
        if inside["n"] > 1:
            lock_ok["race"] = True           # two senders inside at once
        time.sleep(0.001)
        inside["n"] -= 1
        sends.append(data)

    def worker():
        for _ in range(50):
            br._emit(fake_send, b"frame")

    ts = [threading.Thread(target=worker) for _ in range(4)]
    for th in ts:
        th.start()
    for th in ts:
        th.join()
    assert len(sends) == 200 and not lock_ok["race"]
