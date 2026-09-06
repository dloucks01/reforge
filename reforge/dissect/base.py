"""Dissector interface for custom / proprietary protocols.

Built-in protocols come from Scapy. Operators add their own via this interface
(or, later, a declarative dissector-definition format) so any protocol gets the
same tree-view + field-level manipulation as built-ins. "All protocols matter."
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any


@dataclass
class Field:
    name: str
    value: Any
    offset: int          # byte offset within the layer
    length: int          # bytes
    editable: bool = True


@dataclass
class DissectedLayer:
    name: str
    fields: list[Field]
    payload_offset: int


class Dissector(abc.ABC):
    """Turns bytes into a list of editable fields and back."""

    name: str

    @abc.abstractmethod
    def can_dissect(self, data: bytes, context: dict) -> bool:
        """Cheap check: does this dissector apply to these bytes?"""

    @abc.abstractmethod
    def dissect(self, data: bytes) -> DissectedLayer:
        """Parse one layer into fields."""

    @abc.abstractmethod
    def build(self, layer: DissectedLayer) -> bytes:
        """Reserialize a (possibly edited) layer back to bytes."""


_REGISTRY: dict[str, Dissector] = {}


def register(dissector: Dissector) -> None:
    _REGISTRY[dissector.name] = dissector


def registered() -> dict[str, Dissector]:
    return dict(_REGISTRY)
