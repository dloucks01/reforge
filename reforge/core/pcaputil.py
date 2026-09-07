"""Robust pcap reading.

Scapy chooses a pcap's base layer from its DLT via a registry that may be
unpopulated depending on import order, so an Ethernet capture can intermittently
read as Raw — and re-serializing those packets with bytes() then diverges from
the wire. This helper (1) imports the Ethernet layer first so the DLT is always
mapped, and (2) returns each packet's ORIGINAL captured bytes (pkt.original),
never a recomputed serialization. Everything that reads a pcap goes through here.
"""

from __future__ import annotations

from pathlib import Path


def read_frames(path: str | Path) -> list[bytes]:
    """Return the exact captured Ethernet-frame bytes of every packet in a pcap."""
    from reforge.core.scapy_init import warmup
    warmup()
    from scapy.layers.l2 import Ether  # noqa: F401 — ensures DLT1 (Ethernet) is registered
    from scapy.utils import rdpcap

    frames: list[bytes] = []
    for pkt in rdpcap(str(path)):
        original = getattr(pkt, "original", None)
        frames.append(bytes(original) if original else bytes(pkt))
    return frames


def read_packets(path: str | Path) -> list:
    """Return each packet re-dissected from Ethernet (consistent layering)."""
    from scapy.layers.l2 import Ether

    return [Ether(fb) for fb in read_frames(path)]
