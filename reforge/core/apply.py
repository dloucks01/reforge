"""Shared 'run one packet through the engine' logic.

Both the userspace Pipeline (Ethernet frames) and the NFQUEUE runner (IP
payloads) use this, so manipulation behaves identically regardless of the inline
path. Pure function over bytes → result, which makes it exhaustively testable
without root or live traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reforge.core.packet import Packet
from reforge.rules.base import Disposition
from reforge.rules.engine import RuleEngine


@dataclass
class ApplyResult:
    disposition: Disposition
    out: bytes | None = None            # forward bytes (None for drop/hold)
    delay_s: float = 0.0
    extra: list[bytes] = field(default_factory=list)  # injected/duplicated
    matched_rule: str | None = None
    modified: bool = False
    notes: list[str] = field(default_factory=list)


def apply_engine(engine: RuleEngine, raw: bytes, ingress: str = "",
                 link: str = "ether") -> ApplyResult:
    pkt = Packet.from_bytes(raw, ingress=ingress, link=link)
    verdict = engine.evaluate(pkt)

    if verdict.disposition is Disposition.DROP:
        return ApplyResult(Disposition.DROP, None, matched_rule=verdict.matched_rule,
                           notes=verdict.notes)
    if verdict.disposition is Disposition.HOLD:
        return ApplyResult(Disposition.HOLD, None, matched_rule=verdict.matched_rule,
                           notes=verdict.notes)

    modified = pkt.modified
    out = pkt.rebuild()
    extra = [e.rebuild() if e.modified else e.raw for e in verdict.extra_sends]
    return ApplyResult(
        disposition=Disposition.FORWARD,
        out=out,
        delay_s=verdict.delay_s,
        extra=extra,
        matched_rule=verdict.matched_rule,
        modified=modified,
        notes=verdict.notes,
    )
