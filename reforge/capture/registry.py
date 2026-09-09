"""Backend registry and availability probing.

The GUI / Doctor / CLI use this to show which backends are usable on the host
and to auto-select a viable one for a chosen link speed.
"""

from __future__ import annotations

import logging

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import CaptureBackend
from reforge.capture.fanout import FanoutRingBackend
from reforge.capture.pcap import PcapFileBackend
from reforge.capture.perf_backends import AfXdpBackend, DpdkBackend, PfRingBackend
from reforge.capture.rawsocket import RawSocketBackend

# Ordered from most-compatible to fastest. AF_PACKET (live), raw AF_PACKET
# (bytes-level), AF_PACKET fanout (multi-core), and pcap (offline) have full data
# planes that actually run; the kernel-bypass backends detect host capability and
# need the fast-path component to run (see docs/DEPLOYMENT.md).
_REGISTRY: list[type[CaptureBackend]] = [
    AfPacketBackend,
    RawSocketBackend,
    FanoutRingBackend,
    PcapFileBackend,
    AfXdpBackend,
    PfRingBackend,
    DpdkBackend,
]

_PLANNED = [
    ("nfqueue", "NFQUEUE kernel path (Phase 2) — gateway/bridged L3-L7"),
]

# Rough speed ceilings (Mbps) per backend, for recommend_backend().
_SPEED_CEILING = {"af_packet": 2000, "raw_afpacket": 5000, "af_packet_fanout": 10000,
                  "af_xdp": 40000, "pf_ring": 100000, "dpdk": 100000}


def _runnable(name: str) -> bool:
    """Available AND has a working data plane in this build (open() won't raise).

    A perf backend can be *detected* (is_available True) while its zero-copy loop
    is a compiled component absent from this build; recommending it would hand the
    caller a backend that throws at open(). Filter those out here.
    """
    try:
        return get_backend(name).caps.has_dataplane
    except KeyError:
        return False


def recommend_backend(link_mbps: int) -> str:
    """Pick the most-compatible RUNNABLE backend that can plausibly carry `link_mbps`.

    Prefers AF_PACKET when it's fast enough (no special setup), stepping up to
    faster backends only when the link demands it, the host supports them, and
    this build can actually run them. Never returns a detected-but-unbuilt
    fast-path backend (see recommend_with_note for surfacing that case).
    """
    order = ["af_packet", "raw_afpacket", "af_packet_fanout", "af_xdp", "pf_ring", "dpdk"]
    available = {name for name, ok, _ in list_backends() if ok and _runnable(name)}
    for name in order:
        if _SPEED_CEILING.get(name, 0) >= link_mbps and name in available:
            return name
    # nothing runnable meets the rate; return the fastest runnable, else af_packet
    for name in reversed(order):
        if name in available:
            return name
    return "af_packet"


def recommend_with_note(link_mbps: int) -> tuple[str, str]:
    """Like recommend_backend, but also flag when a FASTER backend is detected on
    this host yet needs the fast-path build to run — so the operator/Doctor can
    say 'using raw_afpacket; dpdk detected but needs the fast-path component'."""
    pick = recommend_backend(link_mbps)
    if _SPEED_CEILING.get(pick, 0) >= link_mbps:
        return pick, ""
    # the pick can't meet the rate; is a faster backend detected but unbuilt?
    detected = {name for name, ok, _ in list_backends() if ok}
    for name in ("dpdk", "pf_ring", "af_xdp"):
        if name in detected and not _runnable(name):
            return pick, (f"{name} detected but needs the fast-path build "
                          "(see docs/DEPLOYMENT.md) to reach line rate")
    return pick, ""


def list_interfaces() -> list[str]:
    """Return capture-capable interface names (best-effort, no root needed)."""
    try:
        from scapy.arch import get_if_list

        return sorted(i for i in get_if_list() if i != "lo") or ["lo"]
    except Exception:
        # don't mask a Scapy problem as "no interfaces" — say so
        logging.getLogger("reforge.registry").warning(
            "could not enumerate interfaces", exc_info=True)
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
