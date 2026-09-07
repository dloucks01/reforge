"""Backend registry and availability probing.

The GUI / Doctor / CLI use this to show which backends are usable on the host
and to auto-select a viable one for a chosen link speed.
"""

from __future__ import annotations

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import CaptureBackend
from reforge.capture.pcap import PcapFileBackend
from reforge.capture.perf_backends import AfXdpBackend, DpdkBackend, PfRingBackend
from reforge.capture.rawsocket import RawSocketBackend

# Ordered from most-compatible to fastest. AF_PACKET (live), raw AF_PACKET
# (bytes-level), and pcap (offline) have full data planes; the kernel-bypass
# backends detect host capability and need the fast-path component to actually
# run (see docs/DEPLOYMENT.md).
_REGISTRY: list[type[CaptureBackend]] = [
    AfPacketBackend,
    RawSocketBackend,
    PcapFileBackend,
    AfXdpBackend,
    PfRingBackend,
    DpdkBackend,
]

_PLANNED = [
    ("nfqueue", "NFQUEUE kernel path (Phase 2) — gateway/bridged L3-L7"),
]

# Rough speed ceilings (Mbps) per backend, for recommend_backend().
_SPEED_CEILING = {"af_packet": 2000, "raw_afpacket": 5000,
                  "af_xdp": 40000, "pf_ring": 100000, "dpdk": 100000}


def recommend_backend(link_mbps: int) -> str:
    """Pick the most-compatible backend that can plausibly carry `link_mbps`.

    Prefers AF_PACKET when it's fast enough (no special setup), stepping up to
    faster backends only when the link demands it and the host supports them.
    """
    order = ["af_packet", "raw_afpacket", "af_xdp", "pf_ring", "dpdk"]
    available = {name for name, ok, _ in list_backends() if ok}
    for name in order:
        if _SPEED_CEILING.get(name, 0) >= link_mbps and name in available:
            return name
    # nothing available meets the rate; return the fastest available, else af_packet
    for name in reversed(order):
        if name in available:
            return name
    return "af_packet"


def list_interfaces() -> list[str]:
    """Return capture-capable interface names (best-effort, no root needed)."""
    try:
        from scapy.arch import get_if_list

        return sorted(i for i in get_if_list() if i != "lo") or ["lo"]
    except Exception:
        return []


def list_backends() -> list[tuple[str, bool, str]]:
    """Return (name, available, note) for every known backend."""
    rows: list[tuple[str, bool, str]] = []
    for cls in _REGISTRY:
        ok, note = cls.is_available()
        rows.append((cls.caps.name, ok, note))
    for name, note in _PLANNED:
        rows.append((name, False, note))
    return rows


def get_backend(name: str) -> type[CaptureBackend]:
    for cls in _REGISTRY:
        if cls.caps.name == name:
            return cls
    raise KeyError(f"unknown or unimplemented backend: {name}")
