"""Compiled fast-path component discovery + delegation (docs/FAST-PATH.md)."""

from __future__ import annotations

import textwrap

import pytest

from reforge.capture import fastpath, registry
from reforge.capture.perf_backends import AfXdpBackend, DpdkBackend

_FAKE = textwrap.dedent('''
    from reforge.capture.base import Frame

    def supports(backend):
        return backend == "af_xdp"

    def create(backend, ifaces, **opts):
        if backend != "af_xdp":
            return None
        return _Provider(ifaces)

    class _Provider:
        def __init__(self, ifaces):
            self.ifaces = ifaces; self.opened = False; self.closed = False; self.sent = 0
        def open(self): self.opened = True
        def recv_burst(self, n, t): return [Frame(data=b"xdp", ingress=self.ifaces[0])]
        def send_burst(self, frames): 
            c = len(list(frames)); self.sent += c; return c
        def capture_stats(self): return {"received": 10, "dropped": 1}
        def close(self): self.closed = True
''')


@pytest.fixture
def fake_component(tmp_path, monkeypatch):
    p = tmp_path / "fake_fastpath.py"
    p.write_text(_FAKE)
    monkeypatch.setenv("REFORGE_FASTPATH", str(p))
    return p


# --- no component installed -------------------------------------------------
def test_no_component_backend_open_raises(monkeypatch):
    monkeypatch.delenv("REFORGE_FASTPATH", raising=False)
    assert fastpath.provider_available("af_xdp") is False
    with pytest.raises(NotImplementedError) as e:
        AfXdpBackend(["eth0"]).open()
    assert "FAST-PATH.md" in str(e.value)


# --- component installed ----------------------------------------------------
def test_provider_available_respects_supports(fake_component):
    assert fastpath.provider_available("af_xdp") is True
    assert fastpath.provider_available("dpdk") is False       # supports() said no


def test_backend_delegates_to_provider(fake_component):
    from reforge.capture.base import Frame
    be = AfXdpBackend(["eth0"])
    be.open()
    assert be._provider is not None and be._provider.opened
    frames = be.recv_burst(8, 0.1)
    assert frames and frames[0].data == b"xdp"
    assert be.send_burst([Frame(data=b"x")]) == 1
    assert be.capture_stats() == {"received": 10, "dropped": 1}
    be.close()
    assert be._provider is None


def test_unsupported_backend_still_raises_with_component(fake_component):
    # the fake serves only af_xdp; dpdk must still report missing
    with pytest.raises(NotImplementedError):
        DpdkBackend(["eth0"]).open()


def test_runnable_reflects_installed_component(fake_component):
    assert registry._runnable("af_xdp") is True               # provider present
    assert registry._runnable("dpdk") is False


def test_recommend_steps_up_when_supported_and_installed(fake_component, monkeypatch):
    # simulate a host that also *detects* AF_XDP (is_available would be True)
    monkeypatch.setattr(registry, "list_backends", lambda: [
        ("af_packet", True, ""), ("raw_afpacket", True, ""),
        ("af_packet_fanout", True, ""), ("af_xdp", True, ""),
    ])
    assert registry.recommend_backend(30000) == "af_xdp"      # 40G ceiling, now runnable
