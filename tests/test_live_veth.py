"""Live tests over real kernel sockets using veth pairs.

Opt-in: these create real interfaces, so they run only as root AND with
REFORGE_LIVE=1 set. Normal `pytest` skips them.

    sudo REFORGE_LIVE=1 python -m pytest tests/test_live_veth.py -q

They validate the paths the synthetic backend cannot: the real AF_PACKET capture
socket, real frame injection, and a real userspace bridge forwarding + rewriting
between two interfaces.
"""

from __future__ import annotations

import os
import threading
import time

import pytest

from reforge.testlab.netlab import BRIDGE_LAB, add_pair, del_iface, is_root

pytestmark = pytest.mark.skipif(
    not (is_root() and os.environ.get("REFORGE_LIVE") == "1"),
    reason="live veth tests need root and REFORGE_LIVE=1",
)


def _marker(dport: int, tag: bytes) -> bytes:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    return bytes(Ether(src="02:00:00:00:ab:01", dst="ff:ff:ff:ff:ff:ff")
                 / IP(src="10.7.7.1", dst="10.7.7.2") / UDP(dport=dport) / tag)


def _sniff_for(iface: str, tag: bytes, seconds: float = 3.0) -> list:
    from reforge.capture.afpacket import AfPacketBackend

    be = AfPacketBackend([iface])
    be.open()
    seen: list = []

    def run():
        deadline = time.time() + seconds
        while time.time() < deadline and not seen:
            for f in be.recv_burst(32, 0.3):
                if tag in f.data:
                    seen.append(f)

    t = threading.Thread(target=run)
    t.start()
    return be, t, seen


def test_real_capture_and_inject():
    from scapy.sendrecv import sendp

    add_pair("rf-a", "rf-b")
    try:
        be, t, seen = _sniff_for("rf-a", b"LIVE-CAP")
        time.sleep(0.4)
        marker = _marker(4444, b"LIVE-CAP")
        for _ in range(4):
            sendp(marker, iface="rf-b", verbose=0)
            time.sleep(0.1)
        t.join()
        be.close()
        assert seen, "marker not captured on the real interface"
        assert seen[0].data == marker and seen[0].ingress == "rf-a"
    finally:
        del_iface("rf-a")


def test_real_bridge_forwards_and_rewrites():
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sendp

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules import actions as A
    from reforge.rules import matchers as M
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine

    for a, b in BRIDGE_LAB:
        add_pair(a, b)
    br = None
    try:
        engine = RuleEngine([Rule("rw", M.FieldMatch("UDP", "dport", "eq", 4445),
                                  [A.SetField("IP", "dst", "10.7.7.99")])])
        br = UserspaceBridge("lab-a", "lab-b", engine, armed=True)
        br.start()
        time.sleep(0.8)                                  # let ports open

        be, t, seen = _sniff_for("lab-b-p", b"LIVE-BRIDGE")
        time.sleep(0.4)
        marker = _marker(4445, b"LIVE-BRIDGE")
        for _ in range(4):
            sendp(marker, iface="lab-a-p", verbose=0)    # inject client-side
            time.sleep(0.15)
        t.join()
        be.close()
        assert seen, "frame did not traverse the real bridge"
        assert Ether(seen[0].data)[IP].dst == "10.7.7.99"   # rule rewrote it
        assert br.counters.modified >= 1
    finally:
        if br is not None:
            br.stop()
        for a, _b in BRIDGE_LAB:
            del_iface(a)
