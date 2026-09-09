"""Raw AF_PACKET backend registration + availability."""

from __future__ import annotations

from reforge.capture import registry
from reforge.capture.rawsocket import RawSocketBackend


def test_registered_in_ladder():
    names = {n for n, _, _ in registry.list_backends()}
    assert "raw_afpacket" in names


def test_availability_tuple():
    ok, note = RawSocketBackend.is_available()
    assert isinstance(ok, bool) and note


def test_recommend_uses_raw_for_midrange():
    available = {n for n, ok, _ in registry.list_backends() if ok}
    if "raw_afpacket" in available:
        assert registry.recommend_backend(3000) == "raw_afpacket"


def test_needs_two_ifaces_error():
    try:
        RawSocketBackend([])
        raise AssertionError("expected ValueError")
    except ValueError:
        pass


# --- send_burst egress-field regression (Frame must carry .egress) -----------
def test_frame_has_egress_field():
    """Regression: both send paths read Frame.egress; it must exist and default."""
    from reforge.capture.base import Frame

    f = Frame(data=b"x")
    assert f.egress == ""
    assert Frame(data=b"x", egress="eth1").egress == "eth1"


def test_rawsocket_send_burst_honors_egress(monkeypatch):
    """send_burst must not AttributeError, and must route to Frame.egress."""
    from reforge.capture.base import Frame

    be = RawSocketBackend(["eth0", "eth1"])
    calls = []

    class _FakeSock:
        def __init__(self, iface):
            self.iface = iface

        def send(self, data):
            calls.append((self.iface, bytes(data)))

    monkeypatch.setattr(be, "_sender", lambda iface: _FakeSock(iface))

    # explicit egress is honored; empty egress falls back to the peer iface
    sent = be.send_burst([Frame(data=b"a", egress="eth1"),
                          Frame(data=b"b", ingress="eth0")])
    assert sent == 2
    assert calls[0] == ("eth1", b"a")
    assert calls[1][0] == "eth1"   # fallback: peer of a 2-iface bridge
