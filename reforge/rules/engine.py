"""Ordered rule engine.

Evaluates rules in order against a packet, applies actions, and produces a
Verdict. Supports dry-run (shadow) mode: rules are evaluated and counted but the
packet is never actually modified, for validating a rule set before arming.
"""

from __future__ import annotations

import copy
import logging

from reforge.core.packet import Packet
from reforge.rules.base import Disposition, Rule, Verdict

log = logging.getLogger("reforge.rules")


class RuleEngine:
    def __init__(self, rules: list[Rule] | None = None, dry_run: bool = False):
        self.rules: list[Rule] = rules or []
        self.dry_run = dry_run

    def add(self, rule: Rule) -> None:
        self.rules.append(rule)

    def evaluate(self, pkt: Packet) -> Verdict:
        """Run the ordered pipeline over one packet and return a Verdict."""
        verdict = Verdict()
        working = copy.deepcopy(pkt) if self.dry_run else pkt

        for rule in self.rules:
            if not rule.enabled:
                continue
            try:
                if not rule.match.matches(working):
                    continue
            except Exception:  # a bad match must never break the wire
                log.exception("match error in rule %s", rule.name)
                continue

            rule.hits += 1
            verdict.matched_rule = rule.name

            if self.dry_run:
                verdict.notes.append(f"[dry-run] would apply rule '{rule.name}'")
                continue

            for action in rule.actions:
                try:
                    action.apply(working, verdict)
                except Exception:
                    log.exception("action error in rule %s", rule.name)
            if verdict.disposition is Disposition.DROP:
                break

        return verdict
