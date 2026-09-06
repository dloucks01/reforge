"""Concrete Match implementations for the rule engine.

Structured, field-level matching (plus boolean combinators) so the GUI can build
conditions like `TCP.dport == 80 and IP.src in 10.0.0.0/24` without free-form
code. Any match error evaluates to False (never breaks the wire).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from reforge.core.packet import Packet
from reforge.rules.base import Match

_NUM_OPS = {
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
}


def _coerce(spec_val, actual):
    """Coerce a spec value toward the actual field's type for comparison."""
    if isinstance(actual, int) and isinstance(spec_val, str):
        try:
            return int(spec_val, 0)
        except ValueError:
            return spec_val
    return spec_val


class AllMatch(Match):
    def matches(self, pkt: Packet) -> bool:
        return True


@dataclass
class LayerMatch(Match):
    layer: str

    def matches(self, pkt: Packet) -> bool:
        try:
            return bool(pkt.scapy().haslayer(self.layer))
        except Exception:
            return False


@dataclass
class FieldMatch(Match):
    layer: str
    field: str
    op: str          # eq ne lt le gt ge in contains cidr
    value: object

    def matches(self, pkt: Packet) -> bool:
        try:
            p = pkt.scapy()
            if not p.haslayer(self.layer):
                return False
            actual = p[self.layer].getfieldval(self.field)
        except Exception:
            return False

        op, v = self.op, self.value
        try:
            if op == "eq":
                return actual == _coerce(v, actual)
            if op == "ne":
                return actual != _coerce(v, actual)
            if op in _NUM_OPS:
                return _NUM_OPS[op](actual, _coerce(v, actual))
            if op == "in":
                seq = v if isinstance(v, (list, tuple, set)) else [v]
                return actual in seq
            if op == "contains":
                return str(v) in str(actual)
            if op == "cidr":
                return ipaddress.ip_address(str(actual)) in ipaddress.ip_network(str(v), strict=False)
        except Exception:
            return False
        return False


@dataclass
class AndMatch(Match):
    of: list[Match]

    def matches(self, pkt: Packet) -> bool:
        return all(m.matches(pkt) for m in self.of)


@dataclass
class OrMatch(Match):
    of: list[Match]

    def matches(self, pkt: Packet) -> bool:
        return any(m.matches(pkt) for m in self.of)


@dataclass
class NotMatch(Match):
    inner: Match

    def matches(self, pkt: Packet) -> bool:
        return not self.inner.matches(pkt)
