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
        assert False, "expected ValueError"
    except ValueError:
        pass
