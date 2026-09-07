"""PCAP file backend + export.

A CaptureBackend that replays frames from a pcap/pcapng file. This is how
"pcap import" works, and it lets the whole pipeline and GUI run offline without
root — the backbone of the Phase 1 test story.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from reforge.capture.base import BackendCaps, CaptureBackend, Frame


class PcapFileBackend(CaptureBackend):
    caps = BackendCaps(
        name="pcap_file",
        l2_rewrite=True,
        inject=False,
        max_speed_hint="offline",
        needs_root=False,
        notes="Replays a pcap file; offline, no root needed.",
    )

    def __init__(self, path: str | Path, iface_label: str = "pcap"):
        self.path = str(path)
        self.iface_label = iface_label
        self._frames: list[Frame] = []
        self._pos = 0

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        try:
            import scapy  # noqa: F401
        except Exception as exc:  # pragma: no cover
            return False, f"scapy import failed: {exc}"
        return True, "reads pcap/pcapng offline"

    def open(self) -> None:
        from reforge.core.pcaputil import read_timed_frames

        # Use the exact captured bytes (not a recomputed serialization) so replay
        # matches the wire, and carry each packet's original capture timestamp so
        # the UI shows the real inter-packet timing, not the replay time.
        self._frames = [
            Frame(data=fb, ingress=self.iface_label, meta={"ts": ts})
            for ts, fb in read_timed_frames(self.path)
        ]
        self._pos = 0

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        batch = self._frames[self._pos : self._pos + max_frames]
        self._pos += len(batch)
        return batch

    def send_burst(self, frames: Iterable[Frame]) -> int:
        # Offline source: "sending" is a no-op (frames would go to an export).
        return len(list(frames))

    def close(self) -> None:
        self._frames = []
        self._pos = 0

    @property
    def exhausted(self) -> bool:
        return self._pos >= len(self._frames)


def export_pcap(path: str | Path, frames: Iterable[Frame]) -> int:
    """Write frames to a pcap file, preserving capture timestamps. Returns count."""
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    packets = []
    for f in frames:
        pkt = Ether(f.data)
        ts = f.meta.get("ts") if isinstance(f.meta, dict) else None
        if ts is not None:
            try:
                pkt.time = float(ts)
            except (TypeError, ValueError):
                pass
        packets.append(pkt)
    wrpcap(str(path), packets)
    return len(packets)
