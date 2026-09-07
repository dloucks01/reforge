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


def _tcp_payload_len(scapy_pkt) -> int | None:
    """Length of the TCP payload, or None if this isn't a TCP packet."""
    from scapy.layers.inet import TCP

    if not scapy_pkt.haslayer(TCP):
        return None
    return len(bytes(scapy_pkt[TCP].payload))


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
                 link: str = "ether", seq_fixer=None,
                 recompute_checksums: bool = False) -> ApplyResult:
    pkt = Packet.from_bytes(raw, ingress=ingress, link=link)

    # Capture the original TCP payload length before rules run, so we can tell
    # how much a length-changing edit shifted the stream (for seq/ack fix-ups).
    orig_tcp_paylen = None
    if seq_fixer is not None:
        orig_tcp_paylen = _tcp_payload_len(pkt.scapy())

    verdict = engine.evaluate(pkt)

    if verdict.disposition is Disposition.DROP:
        return ApplyResult(Disposition.DROP, None, matched_rule=verdict.matched_rule,
                           notes=verdict.notes)
    if verdict.disposition is Disposition.HOLD:
        return ApplyResult(Disposition.HOLD, None, matched_rule=verdict.matched_rule,
                           notes=verdict.notes)

    # Stateful TCP seq/ack fix-ups: shift this segment by deltas we already
    # introduced in the flow, then record any new delta from this edit.
    if seq_fixer is not None and orig_tcp_paylen is not None:
        from scapy.layers.inet import TCP

        sc = pkt.scapy()
        orig_seq = sc[TCP].seq                    # capture BEFORE apply shifts it
        changed = seq_fixer.apply(sc)
        delta = _tcp_payload_len(sc) - orig_tcp_paylen
        if changed or delta:
            pkt.modified = True
        if delta:
            seq_fixer.note_length_change(sc, delta, orig_seq=orig_seq)

    modified = pkt.modified
    if recompute_checksums:
        pkt.modified = True   # force rebuild to recompute lengths/checksums
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
