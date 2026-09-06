"""Backend registry and availability probing.

The GUI / Doctor / CLI use this to show which backends are usable on the host
and to auto-select a viable one for a chosen link speed.
"""

from __future__ import annotations

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import CaptureBackend
from reforge.capture.pcap import PcapFileBackend

# Ordered from most-compatible to fastest. AF_PACKET (live) and pcap (offline)
# are implemented; the rest are registered as placeholders so the ladder is
# visible in the UI and Doctor.
_REGISTRY: list[type[CaptureBackend]] = [
    AfPacketBackend,
    PcapFileBackend,
]

# Names of backends planned but not yet implemented (shown as unavailable).
_PLANNED = [
    ("af_xdp", "AF_XDP zero-copy (Phase 8) — 10-40G, needs XDP-capable driver"),
    ("pf_ring", "PF_RING ZC (Phase 8) — 10-100G, needs PF_RING modules"),
    ("dpdk", "DPDK poll-mode (Phase 8) — 100G, hugepages + NIC binding"),
    ("nfqueue", "NFQUEUE kernel path (Phase 2) — gateway/bridged L3-L7"),
]


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
