"""Shared state for a running scenario.

Steps read/write this: the asset inventory (shared with recon/scan), harvested
credentials, scan results, an event timeline, and the background attack runners
the scenario started (stopped on teardown).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from reforge.recon.assets import AssetInventory


@dataclass
class Event:
    t: float
    step: str
    detail: str


class ScenarioContext:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.inventory = AssetInventory()
        self.creds: list = []
        self.scans: dict = {}
        self.events: list[Event] = []
        self.background: list = []          # runners with .stop()
        self.notes: list[str] = []
        self._t0 = time.time()

    def event(self, step: str, detail: str = "") -> None:
        self.events.append(Event(round(time.time() - self._t0, 3), step, detail))

    def add_creds(self, creds: list) -> None:
        for c in creds:
            self.creds.append(c)

    def add_background(self, runner) -> None:
        self.background.append(runner)

    def teardown(self) -> None:
        for bg in reversed(self.background):
            try:
                bg.stop()
            except Exception:
                pass
        self.background.clear()
