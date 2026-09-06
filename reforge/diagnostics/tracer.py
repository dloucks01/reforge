"""Packet-path tracer — answers "why didn't my rule match / why was it dropped".

Runs a packet through the rule engine with instrumentation, recording for every
rule whether it matched (and if not, a best-effort reason) and what each action
did, plus the final disposition. Pure over bytes, so it is fully testable and is
what the GUI Diagnostics tab shows for a selected packet.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reforge.core.packet import Packet
from reforge.rules import matchers as M
from reforge.rules.base import Disposition, Verdict
from reforge.rules.engine import RuleEngine


@dataclass
class RuleStep:
    name: str
    matched: bool
    reason: str = ""            # why it did/didn't match
    actions: list[str] = field(default_factory=list)


@dataclass
class PacketTrace:
    disposition: str
    matched_rule: str | None
    modified: bool
    out_len: int | None
    steps: list[RuleStep] = field(default_factory=list)


def _why_not(match, pkt: Packet) -> str:
    """Best-effort explanation for a FieldMatch/LayerMatch that didn't fire."""
    try:
        if isinstance(match, M.LayerMatch):
            return f"no {match.layer} layer"
        if isinstance(match, M.FieldMatch):
            p = pkt.scapy()
            if not p.haslayer(match.layer):
                return f"no {match.layer} layer"
            actual = p[match.layer].getfieldval(match.field)
            return f"{match.layer}.{match.field}={actual} not {match.op} {match.value}"
    except Exception:
        pass
    return "condition false"


def trace(engine: RuleEngine, raw: bytes, link: str = "ether") -> PacketTrace:
    pkt = Packet.from_bytes(raw, link=link)
    verdict = Verdict()
    steps: list[RuleStep] = []

    stopped = False
    for rule in engine.rules:
        if stopped:
            steps.append(RuleStep(rule.name, False, reason="not evaluated (dropped earlier)"))
            continue
        if not rule.enabled:
            steps.append(RuleStep(rule.name, False, reason="disabled"))
            continue
        try:
            matched = rule.match.matches(pkt)
        except Exception as exc:
            steps.append(RuleStep(rule.name, False, reason=f"match error: {exc}"))
            continue
        if not matched:
            steps.append(RuleStep(rule.name, False, reason=_why_not(rule.match, pkt)))
            continue

        verdict.matched_rule = rule.name
        before = len(verdict.notes)
        for action in rule.actions:
            try:
                action.apply(pkt, verdict)
            except Exception as exc:
                verdict.notes.append(f"action error: {exc}")
        steps.append(RuleStep(rule.name, True, actions=list(verdict.notes[before:])))
        if verdict.disposition is Disposition.DROP:
            stopped = True

    modified = pkt.modified
    out_len = None
    if verdict.disposition is Disposition.FORWARD:
        out_len = len(pkt.rebuild())
    return PacketTrace(
        disposition=verdict.disposition.value,
        matched_rule=verdict.matched_rule,
        modified=modified,
        out_len=out_len,
        steps=steps,
    )


def format_trace(t: PacketTrace) -> str:
    lines = [f"disposition: {t.disposition}"
             + (f"  (matched {t.matched_rule})" if t.matched_rule else "  (no rule matched)")]
    if t.out_len is not None:
        lines[0] += f"  out={t.out_len}B" + ("  [modified]" if t.modified else "")
    for s in t.steps:
        if s.matched:
            lines.append(f"  ✓ {s.name}: " + (", ".join(s.actions) or "matched"))
        else:
            lines.append(f"  ✗ {s.name}: {s.reason}")
    return "\n".join(lines)
