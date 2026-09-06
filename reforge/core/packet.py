"""Packet model — a thin wrapper over a Scapy packet.

Keeps a single source of truth for the bytes while giving rules and the GUI a
stable interface for field access and (re)serialization.

`link` selects the base layer used to dissect the bytes:
- "ether": frames from AF_PACKET / the userspace bridge (start at Ethernet).
- "ip":    payloads from NFQUEUE (start at IPv4/IPv6, no L2 header).

On rebuild, length/checksum fields are cleared so Scapy recomputes them, unless
a field name is pinned (to intentionally forward a wrong checksum/length).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_AUTO_FIELDS = ("len", "chksum", "plen", "ulen")


@dataclass
class Packet:
    raw: bytes
    ingress: str = ""
    egress: str = ""
    link: str = "ether"
    _scapy: Any = None
    pinned_fields: set[str] = field(default_factory=set)
    modified: bool = False

    @classmethod
    def from_bytes(cls, data: bytes, ingress: str = "", link: str = "ether") -> "Packet":
        return cls(raw=bytes(data), ingress=ingress, link=link)

    def _base_class(self):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        from scapy.layers.l2 import Ether

        if self.link == "ip":
            # Distinguish IPv4/IPv6 by the version nibble.
            if self.raw and (self.raw[0] >> 4) == 6:
                return IPv6
            return IP
        return Ether

    def scapy(self) -> Any:
        if self._scapy is None:
            self._scapy = self._base_class()(self.raw)
        return self._scapy

    def get_field(self, layer: str, field_name: str) -> Any:
        return self.scapy()[layer].getfieldval(field_name)

    def set_field(self, layer: str, field_name: str, value: Any) -> None:
        pkt = self.scapy()
        setattr(pkt[layer], field_name, value)
        self.modified = True

    def rebuild(self) -> bytes:
        """Reserialize, recomputing checksums/lengths (except pinned fields)."""
        if self._scapy is None or not self.modified:
            return self.raw
        for layer in _iter_layers(self._scapy):
            for auto in _AUTO_FIELDS:
                if auto in self.pinned_fields:
                    continue
                if hasattr(layer, auto) and layer.getfieldval(auto) is not None:
                    try:
                        delattr(layer, auto)
                    except Exception:
                        pass
        self.raw = bytes(self._scapy)
        # keep the dissected view consistent with the new bytes
        self._scapy = None
        self.modified = False
        return self.raw


def _iter_layers(pkt: Any):
    layer = pkt
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        yield layer
        layer = layer.payload if getattr(layer, "payload", None) is not None else None
