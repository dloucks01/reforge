"""Fuzzing campaign runner.

Ties strategies + a send/receive function + a monitor into a reproducible loop
that records findings (with the seed to reproduce each) and evolves a corpus
toward inputs that produce novel behavior (response-feedback guidance).

Offline-testable: pass any `send_receive(bytes) -> Response`; a fake target lets
the whole engine be tested without root or a live host.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

from reforge.fuzzing import monitor as mon
from reforge.fuzzing.strategies import DEFAULT_STRATEGIES, FuzzCase, Mutator


@dataclass
class Finding:
    case: FuzzCase
    classification: str
    iteration: int


@dataclass
class CampaignReport:
    sent: int = 0
    findings: list[Finding] = field(default_factory=list)
    corpus_size: int = 0
    by_class: dict = field(default_factory=dict)

    def summary(self) -> str:
        lines = [f"sent={self.sent}  findings={len(self.findings)}  corpus={self.corpus_size}"]
        for k, v in sorted(self.by_class.items()):
            lines.append(f"  {k}: {v}")
        for f in self.findings[:20]:
            lines.append(f"  [{f.classification}] iter={f.iteration} strat={f.case.strategy} "
                         f"seed={f.case.seed} ({len(f.case.data)}B)")
        return "\n".join(lines)


class FuzzCampaign:
    def __init__(self, seed_bytes: bytes, send_receive: Callable,
                 strategies: list[Mutator] | None = None,
                 monitor: mon.TargetMonitor | None = None,
                 iterations: int = 100, seed: int = 0, link: str = "ether",
                 extra_seeds: list[bytes] | None = None):
        self.corpus: list[bytes] = [seed_bytes] + list(extra_seeds or [])
        self.send_receive = send_receive
        self.strategies = strategies or DEFAULT_STRATEGIES
        self.monitor = monitor or mon.TargetMonitor()
        self.iterations = iterations
        self.rng = random.Random(seed)
        self.link = link

    def run(self) -> CampaignReport:
        report = CampaignReport()
        seen_classes: set[str] = set()

        for i in range(self.iterations):
            base = self.rng.choice(self.corpus)
            strat = self.rng.choice(self.strategies)
            case_seed = self.rng.randrange(2**31)
            data = strat.mutate(base, random.Random(case_seed), self.link)
            case = FuzzCase(data=data, seed=case_seed, strategy=strat.name, base=base)

            resp = self.send_receive(data)
            cls = self.monitor.classify(resp)
            report.sent += 1
            report.by_class[cls] = report.by_class.get(cls, 0) + 1

            if mon.is_finding(cls):
                report.findings.append(Finding(case, cls, i))
            # response-feedback: keep inputs that produced a new behavior class
            if cls not in seen_classes:
                seen_classes.add(cls)
                if len(self.corpus) < 1000:
                    self.corpus.append(data)

        report.corpus_size = len(self.corpus)
        return report

    def reproduce(self, case: FuzzCase) -> bytes:
        """Rebuild a case's bytes from its base + strategy + seed (determinism)."""
        strat = next(s for s in self.strategies if s.name == case.strategy)
        return strat.mutate(case.base, random.Random(case.seed), self.link)
