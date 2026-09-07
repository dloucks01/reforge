"""Scenario runner — execute a declarative attack chain and build a report."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from reforge.scenario.context import ScenarioContext
from reforge.scenario.report import Report, build_report
from reforge.scenario.steps import STEPS

log = logging.getLogger("reforge.scenario")


class ScenarioRunner:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.ctx = ScenarioContext(dry_run=dry_run)

    def run(self, spec: dict) -> Report:
        techniques: set[str] = set()
        for st in spec.get("steps", []):
            stype = st.get("type")
            sd = STEPS.get(stype)
            if sd is None:
                self.ctx.event(stype or "?", "(unknown step; skipped)")
                continue
            if sd.attack:
                techniques.add(sd.attack)
            if sd.needs_root and self.dry_run:
                self.ctx.event(stype, "(dry-run: skipped, needs root)")
                continue
            try:
                sd.fn(self.ctx, st.get("params", {}))
            except Exception as exc:
                self.ctx.event(stype, f"error: {exc}")
                log.exception("step %s failed", stype)

        # let background attacks run while collecting, if requested
        dwell = float(spec.get("run_seconds", 0))
        if dwell and not self.dry_run:
            time.sleep(dwell)

        self.ctx.teardown()
        return build_report(self.ctx, spec.get("name", "scenario"), sorted(techniques))


def load_scenario(path: str | Path) -> dict:
    import json

    p = Path(path)
    text = p.read_text()
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml

            return yaml.safe_load(text)
        except ImportError as exc:
            raise RuntimeError("PyYAML not available; use a .json scenario") from exc
    return json.loads(text)
