"""Packet model — a thin wrapper over a Scapy packet.

Keeps a single source of truth for the bytes while giving rules and the GUI a
stable interface for field access and (re)serialization. On serialize, Scapy
recomputes lengths/checksums unless a field was explicitly pinned.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Packet:
    """Wraps raw bytes and (lazily) a dissected Scapy packet."""

    raw: bytes
    ingress: str = ""
    egress: str = ""
    _scapy: Any = None
    pinned_fields: set[str] = field(default_factory=set)  # fields to leave as-is
    modified: bool = False

    @classmethod
    def from_bytes(cls, data: bytes, ingress: str = "") -> "Packet":
        return cls(raw=data, ingress=ingress)

    def scapy(self) -> Any:
        """Dissect lazily with Scapy (Ether at L2)."""
        if self._scapy is None:
            from scapy.layers.l2 import Ether

            self._scapy = Ether(self.raw)
        return self._scapy

    def get_field(self, layer: str, field_name: str) -> Any:
        pkt = self.scapy()
        return pkt[layer].getfieldval(field_name)

    def set_field(self, layer: str, field_name: str, value: Any) -> None:
        pkt = self.scapy()
        setattr(pkt[layer], field_name, value)
        self.modified = True

    def rebuild(self) -> bytes:
        """Reserialize from the dissected packet, recomputing checksums/lengths.

        Pinned fields are left untouched (Scapy keeps explicit values). Deleting
        auto-computed fields before build lets Scapy recompute them.
        """
        if self._scapy is None or not self.modified:
            return self.raw
        pkt = self._scapy
        for auto in ("len", "chksum"):
            if auto in self.pinned_fields:
                continue
            # best-effort: clear so Scapy recomputes on build
            for layer in _iter_layers(pkt):
                if hasattr(layer, auto):
                    try:
                        layer.__delattr__(auto)
                    except Exception:
                        pass
        self.raw = bytes(pkt)
        return self.raw


def _iter_layers(pkt: Any):
    layer = pkt
    while layer:
        yield layer
        layer = layer.payload if getattr(layer, "payload", None) else None
        if layer.__class__.__name__ == "NoPayload":
            break
