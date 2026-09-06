"""Concrete Action implementations.

Actions mutate the Packet and/or the Verdict. Length/checksum recomputation is
handled centrally by Packet.rebuild() after all actions run, so actions just
edit fields/payload and set flags.
"""

from __future__ import annotations

from dataclasses import dataclass

from reforge.core.packet import Packet
from reforge.rules.base import Action, Disposition, Verdict


def _as_bytes(v) -> bytes:
    """Accept bytes, a hex string ('0x..' or 'de:ad'), or utf-8 text."""
    if isinstance(v, bytes):
        return v
    s = str(v)
    if s.startswith("0x"):
        return bytes.fromhex(s[2:])
    if all(c in "0123456789abcdefABCDEF:" for c in s) and ":" in s:
        return bytes.fromhex(s.replace(":", ""))
    return s.encode()


@dataclass
class SetField(Action):
    layer: str
    field: str
    value: object

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        p = pkt.scapy()
        if not p.haslayer(self.layer):
            return
        actual = p[self.layer].getfieldval(self.field)
        value = self.value
        if isinstance(actual, int) and isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                pass
        pkt.set_field(self.layer, self.field, value)
        verdict.notes.append(f"set {self.layer}.{self.field}={value!r}")


@dataclass
class PayloadReplace(Action):
    find: object
    replace: object
    count: int = -1     # -1 = all occurrences

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        from scapy.packet import Raw

        p = pkt.scapy()
        if not p.haslayer(Raw):
            return
        load = bytes(p[Raw].load)
        find, repl = _as_bytes(self.find), _as_bytes(self.replace)
        if find not in load:
            return
        new = load.replace(find, repl) if self.count < 0 else load.replace(find, repl, self.count)
        p[Raw].load = new
        pkt.modified = True
        verdict.notes.append(f"payload {find!r}->{repl!r}")


@dataclass
class Drop(Action):
    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        verdict.disposition = Disposition.DROP
        verdict.notes.append("drop")


@dataclass
class Hold(Action):
    """Divert to the interactive intercept queue (Phase 4)."""

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        verdict.disposition = Disposition.HOLD
        verdict.notes.append("hold")


@dataclass
class Delay(Action):
    seconds: float

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        verdict.delay_s = max(verdict.delay_s, float(self.seconds))
        verdict.notes.append(f"delay {self.seconds}s")


@dataclass
class Duplicate(Action):
    times: int = 1

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        raw = bytes(pkt.scapy())
        for _ in range(max(1, self.times)):
            verdict.extra_sends.append(Packet.from_bytes(raw, link=pkt.link))
        verdict.notes.append(f"duplicate x{self.times}")


@dataclass
class Plugin(Action):
    """Run an operator-registered plugin transform on the packet."""

    name: str

    def apply(self, pkt: Packet, verdict: Verdict) -> None:
        from reforge.plugins import transform

        fn = transform(self.name)
        if fn is None:
            verdict.notes.append(f"plugin '{self.name}' not loaded")
            return
        fn(pkt.scapy())
        pkt.modified = True
        verdict.notes.append(f"plugin {self.name}")
