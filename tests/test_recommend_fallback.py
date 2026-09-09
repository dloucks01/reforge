"""recommend_backend never picks a detected-but-unbuilt fast-path backend, and
recommend_with_note surfaces that case (2026-09 review §2.3)."""

from __future__ import annotations

from reforge.capture import registry as R


def test_never_recommends_perf_backend_even_when_detected(monkeypatch):
    # simulate a host where dpdk/pf_ring/af_xdp all "detect" as available
    monkeypatch.setattr(R, "list_backends", lambda: [
        ("af_packet", True, ""), ("raw_afpacket", True, ""),
        ("af_xdp", True, ""), ("pf_ring", True, ""), ("dpdk", True, ""),
    ])
    # even at 100G, the pick is the fastest RUNNABLE backend (raw AF_PACKET),
    # never dpdk (whose open() would raise without the fast-path build)
    assert R.recommend_backend(100000) == "raw_afpacket"


def test_recommend_with_note_flags_unbuilt_fastpath(monkeypatch):
    monkeypatch.setattr(R, "list_backends", lambda: [
        ("af_packet", True, ""), ("raw_afpacket", True, ""),
        ("dpdk", True, ""),
    ])
    pick, note = R.recommend_with_note(100000)
    assert pick == "raw_afpacket"
    assert "dpdk detected" in note and "fast-path build" in note


def test_recommend_with_note_no_note_when_rate_met(monkeypatch):
    monkeypatch.setattr(R, "list_backends", lambda: [("af_packet", True, "")])
    pick, note = R.recommend_with_note(1000)
    assert pick == "af_packet" and note == ""
