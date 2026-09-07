"""PCAP backend + export round-trip tests (offline, no root)."""

from __future__ import annotations

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from reforge.capture.base import Frame
from reforge.capture.pcap import PcapFileBackend, export_pcap


def _frames(n: int) -> list[Frame]:
    return [
        Frame(data=bytes(Ether() / IP(dst=f"10.0.0.{i}") / UDP(dport=1000 + i)))
        for i in range(n)
    ]


def test_export_then_read_roundtrip(tmp_path):
    frames = _frames(5)
    path = tmp_path / "cap.pcap"
    written = export_pcap(path, frames)
    assert written == 5

    backend = PcapFileBackend(path)
    ok, _ = backend.is_available()
    assert ok
    backend.open()
    got = backend.recv_burst(max_frames=100)
    assert len(got) == 5
    assert backend.exhausted
    # bytes preserved
    assert got[0].data == frames[0].data
    backend.close()


def test_recv_burst_paginates(tmp_path):
    path = tmp_path / "cap.pcap"
    export_pcap(path, _frames(10))
    backend = PcapFileBackend(path)
    backend.open()
    first = backend.recv_burst(max_frames=4)
    second = backend.recv_burst(max_frames=4)
    third = backend.recv_burst(max_frames=4)
    assert (len(first), len(second), len(third)) == (4, 4, 2)
    assert backend.exhausted
    backend.close()


def test_pcap_timestamps_preserved(tmp_path):
    # frames carrying explicit capture timestamps survive export -> import,
    # so replayed pcaps show real inter-packet timing (not the replay clock).
    frames = [
        Frame(data=bytes(Ether() / IP(dst=f"10.0.0.{i}") / UDP(dport=1000 + i)),
              meta={"ts": 1000.0 + i * 100})
        for i in range(3)
    ]
    path = tmp_path / "timed.pcap"
    export_pcap(path, frames)

    backend = PcapFileBackend(path)
    backend.open()
    got = backend.recv_burst(max_frames=10)
    assert [f.meta["ts"] for f in got] == [1000.0, 1100.0, 1200.0]
    backend.close()
