"""Synthetic capture backend — replay generated traffic as a live feed.

Implements the CaptureBackend interface, so the whole GUI and pipeline run
against realistic traffic with no NIC and no root. Frames are released on a
wall-clock schedule derived from their timestamps (scaled by `speed`), so the
capture looks live: packets arrive over time, the Time column shows real deltas,
and credentials/recon accrue as they would on a real segment.
"""

from __future__ import annotations

import time
from collections.abc import Iterable

from reforge.capture.base import BackendCaps, CaptureBackend, Frame


class SyntheticBackend(CaptureBackend):
    caps = BackendCaps(
        name="synthetic",
        l2_rewrite=True,
        inject=False,
        max_speed_hint="offline",
        needs_root=False,
        notes="Replays generated traffic; offline test/demo lab, no root.",
    )

    def __init__(self, frames: list[tuple[float, bytes]] | None = None,
                 *, speed: float = 1.0, loop: bool = False, iface_label: str = "lab0"):
        from reforge.testlab.traffic import mixed_scenario

        self._timed = list(frames if frames is not None else mixed_scenario())
        self._timed.sort(key=lambda tf: tf[0])
        self.speed = max(0.01, speed)
        self.loop = loop
        self.iface_label = iface_label
        self._pos = 0
        self._start = 0.0
        self._t0 = self._timed[0][0] if self._timed else 0.0
        self._epoch = 0.0

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        return True, "always available (offline synthetic traffic)"

    def open(self) -> None:
        self._pos = 0
        self._start = time.monotonic()
        self._epoch = time.time()

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        if not self._timed:
            return []
        elapsed = (time.monotonic() - self._start) * self.speed
        out: list[Frame] = []
        while len(out) < max_frames and self._pos < len(self._timed):
            ts, data = self._timed[self._pos]
            if (ts - self._t0) > elapsed:
                break                           # not due yet — arrives later
            self._pos += 1
            # present a real wall-clock timestamp so the UI shows sensible times
            out.append(Frame(data=data, ingress=self.iface_label,
                             meta={"ts": self._epoch + (ts - self._t0)}))
        if self._pos >= len(self._timed) and self.loop:
            self._pos = 0                       # replay from the top
            self._start = time.monotonic()
            self._epoch = time.time()
        return out

    def send_burst(self, frames: Iterable[Frame]) -> int:
        return len(list(frames))                # offline source: nothing transmitted

    def close(self) -> None:
        self._pos = 0

    @property
    def exhausted(self) -> bool:
        return not self.loop and self._pos >= len(self._timed)
