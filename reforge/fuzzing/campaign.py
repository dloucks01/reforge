"""Fuzzing campaign runner.

Ties strategies + a send/receive function + a monitor into a reproducible loop
that records findings (with the seed to reproduce each) and evolves a corpus
toward inputs that produce novel behavior (response-feedback guidance).

Beyond the basic loop it supports:
- **stateful fuzzing** — a scripted `prefix` of valid packets is replayed before
  each fuzz case, to drive the target into a deep state before mutating.
- **rate/pacing + a time budget** — `rate` cases/sec and `max_seconds`.
- **per-field coverage** — which header fields the campaign has hit, from the
  mutators' annotations.
- **minimization** — shrink a finding to a minimal repro (see `minimize`).
- **persistence** — save/load the corpus and findings for replay.

Offline-testable: pass any `send_receive(bytes) -> Response`; a fake target lets
the whole engine be tested without root or a live host.
"""

from __future__ import annotations

import base64
import json
import random
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
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
    coverage: dict = field(default_factory=dict)   # "Layer.field" -> times mutated
    elapsed: float = 0.0

    def summary(self) -> str:
        lines = [f"sent={self.sent}  findings={len(self.findings)}  "
                 f"corpus={self.corpus_size}  fields={len(self.coverage)}  "
                 f"elapsed={self.elapsed:.2f}s"]
        for k, v in sorted(self.by_class.items()):
            lines.append(f"  {k}: {v}")
        if self.coverage:
            lines.append("  field coverage:")
            for fld, cnt in sorted(self.coverage.items(), key=lambda kv: -kv[1])[:15]:
                lines.append(f"    {fld}: {cnt}")
        for f in self.findings[:20]:
            lines.append(f"  [{f.classification}] iter={f.iteration} strat={f.case.strategy} "
                         f"seed={f.case.seed} ({len(f.case.data)}B)")
        return "\n".join(lines)


class FuzzCampaign:
    def __init__(self, seed_bytes: bytes, send_receive: Callable,
                 strategies: list[Mutator] | None = None,
                 monitor: mon.TargetMonitor | None = None,
                 iterations: int = 100, seed: int = 0, link: str = "ether",
                 extra_seeds: list[bytes] | None = None,
                 prefix: list[bytes] | Callable[[random.Random], list[bytes]] | None = None,
                 rate: float = 0.0, max_seconds: float | None = None):
        self.corpus: list[bytes] = [seed_bytes] + list(extra_seeds or [])
        self.send_receive = send_receive
        self.strategies = strategies or DEFAULT_STRATEGIES
        self.monitor = monitor or mon.TargetMonitor()
        self.iterations = iterations
        self.rng = random.Random(seed)
        self.link = link
        self.prefix = prefix                 # stateful: valid packets sent before each case
        self.rate = rate                     # cases/sec; 0 = unlimited
        self.max_seconds = max_seconds       # wall-clock budget; None = no limit
        self._last_report: CampaignReport | None = None

    # -- stateful prefix -----------------------------------------------------
    def _prefix_packets(self, rng: random.Random) -> list[bytes]:
        if self.prefix is None:
            return []
        if callable(self.prefix):
            return list(self.prefix(rng))
        return list(self.prefix)

    def _drive_to_state(self, rng: random.Random) -> None:
        for pkt in self._prefix_packets(rng):
            self.send_receive(pkt)

    # -- main loop -----------------------------------------------------------
    def run(self) -> CampaignReport:
        report = CampaignReport()
        seen_classes: set[str] = set()
        start = time.monotonic()
        interval = (1.0 / self.rate) if self.rate and self.rate > 0 else 0.0

        for i in range(self.iterations):
            if self.max_seconds is not None and (time.monotonic() - start) >= self.max_seconds:
                break
            base = self.rng.choice(self.corpus)
            strat = self.rng.choice(self.strategies)
            case_seed = self.rng.randrange(2**31)
            case_rng = random.Random(case_seed)
            # replay the valid prefix to reach a deep protocol state, then fuzz
            self._drive_to_state(case_rng)
            data, meta = strat.mutate_annotated(base, case_rng, self.link)
            case = FuzzCase(data=data, seed=case_seed, strategy=strat.name, base=base)

            fld = meta.get("field")
            if fld:
                report.coverage[fld] = report.coverage.get(fld, 0) + 1

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

            if interval:
                time.sleep(interval)

        report.corpus_size = len(self.corpus)
        report.elapsed = time.monotonic() - start
        self._last_report = report
        return report

    def reproduce(self, case: FuzzCase) -> bytes:
        """Rebuild a case's bytes from its base + strategy + seed (determinism).

        Mirrors run(): the prefix draws from the same case RNG before the mutation,
        so a stateful case reproduces the exact mutated bytes.
        """
        strat = next(s for s in self.strategies if s.name == case.strategy)
        case_rng = random.Random(case.seed)
        self._prefix_packets(case_rng)      # consume the same RNG draws as run()
        return strat.mutate(case.base, case_rng, self.link)

    # -- minimization --------------------------------------------------------
    def minimize(self, case: FuzzCase) -> bytes:
        """Shrink a finding's bytes to a minimal input that still misbehaves,
        replaying the campaign's stateful prefix on each trial."""
        from reforge.fuzzing.minimize import ddmin, still_anomalous

        prefix = self._prefix_packets(random.Random(case.seed))
        predicate = still_anomalous(self.send_receive, prefix)
        return ddmin(case.data, predicate)

    # -- persistence ---------------------------------------------------------
    def save(self, directory: str | Path) -> None:
        """Persist the corpus and last run's findings for replay/triage."""
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        (d / "corpus.json").write_text(json.dumps(
            [base64.b64encode(c).decode() for c in self.corpus], indent=0))
        findings = self._last_report.findings if self._last_report else []
        (d / "findings.json").write_text(json.dumps([
            {"classification": f.classification, "iteration": f.iteration,
             "seed": f.case.seed, "strategy": f.case.strategy,
             "base": base64.b64encode(f.case.base).decode(),
             "data": base64.b64encode(f.case.data).decode()}
            for f in findings], indent=2))

    def load_corpus(self, directory: str | Path) -> int:
        """Load a saved corpus (extending the current one). Returns count added."""
        p = Path(directory) / "corpus.json"
        if not p.exists():
            return 0
        entries = [base64.b64decode(s) for s in json.loads(p.read_text())]
        self.corpus.extend(entries)
        return len(entries)


def load_findings(directory: str | Path) -> list[Finding]:
    """Load persisted findings as replayable Finding objects."""
    p = Path(directory) / "findings.json"
    if not p.exists():
        return []
    out: list[Finding] = []
    for d in json.loads(p.read_text()):
        case = FuzzCase(data=base64.b64decode(d["data"]), seed=int(d["seed"]),
                        strategy=d["strategy"], base=base64.b64decode(d["base"]))
        out.append(Finding(case, d["classification"], int(d["iteration"])))
    return out
