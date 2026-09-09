"""AfPacketBackend send_burst: Frame.egress routing regression."""

from __future__ import annotations

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import Frame


def test_send_burst_honors_egress(monkeypatch):
    be = AfPacketBackend(["eth0", "eth1"])
    calls = []

    class _FakeSock:
        def __init__(self, iface):
            self.iface = iface

        def send(self, pkt):
            calls.append((self.iface, bytes(pkt)))

    monkeypatch.setattr(be, "_sender", lambda iface: _FakeSock(iface))

    sent = be.send_burst([Frame(data=b"\x00" * 14, egress="eth1"),
                          Frame(data=b"\x00" * 14)])
    assert sent == 2
    assert calls[0][0] == "eth1"           # explicit egress honored
    assert calls[1][0] == "eth1"           # fallback to peer iface
