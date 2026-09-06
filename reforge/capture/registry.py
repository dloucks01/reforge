"""Backend registry and availability probing.

The GUI / Doctor / CLI use this to show which backends are usable on the host
and to auto-select a viable one for a chosen link speed.
"""

from __future__ import annotations

from reforge.capture.afpacket import AfPacketBackend
from reforge.capture.base import CaptureBackend

# Ordered from most-compatible to fastest. Only AF_PACKET is implemented in
# Phase 0; the rest are registered as placeholders so the ladder is visible.
_REGISTRY: list[type[CaptureBackend]] = [
    AfPacketBackend,
]

# Names of backends planned but not yet implemented (shown as unavailable).
_PLANNED = [
    ("af_xdp", "AF_XDP zero-copy (Phase 8) — 10-40G, needs XDP-capable driver"),
    ("pf_ring", "PF_RING ZC (Phase 8) — 10-100G, needs PF_RING modules"),
    ("dpdk", "DPDK poll-mode (Phase 8) — 100G, hugepages + NIC binding"),
    ("nfqueue", "NFQUEUE kernel path (Phase 2) — gateway/bridged L3-L7"),
]


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
