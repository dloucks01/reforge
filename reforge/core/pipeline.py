"""The inline pipeline skeleton: capture -> rules -> forward.

Phase 0 wires the shape and counters only; the real threaded, burst-oriented,
backpressured loop lands in Phases 2-3. The counters here are what the
diagnostics health dashboard reads.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from reforge.capture.base import CaptureBackend, Frame
from reforge.core.packet import Packet
from reforge.rules.base import Disposition
from reforge.rules.engine import RuleEngine

log = logging.getLogger("reforge.pipeline")


@dataclass
class Counters:
    """Live counters surfaced in the health dashboard and diagnostic bundle."""

    captured: int = 0
    forwarded: int = 0
    dropped: int = 0
    held: int = 0
    modified: int = 0
    injected: int = 0
    errors: int = 0
    started_at: float = field(default_factory=time.time)

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class Pipeline:
    def __init__(self, backend: CaptureBackend, engine: RuleEngine):
        self.backend = backend
        self.engine = engine
        self.counters = Counters()
        self._running = False

    def process_one(self, frame: Frame) -> list[Frame]:
        """Run a single frame through the engine and return frames to send."""
        self.counters.captured += 1
        pkt = Packet.from_bytes(frame.data, ingress=frame.ingress)
        verdict = self.engine.evaluate(pkt)

        if verdict.disposition is Disposition.DROP:
            self.counters.dropped += 1
            return []
        if verdict.disposition is Disposition.HOLD:
            self.counters.held += 1
            return []  # goes to the interception queue (Phase 4)

        out = [Frame(data=pkt.rebuild(), ingress=frame.ingress, meta=frame.meta)]
        if pkt.modified:
            self.counters.modified += 1
        for extra in verdict.extra_sends:
            out.append(Frame(data=extra.rebuild(), ingress=frame.ingress))
            self.counters.injected += 1
        self.counters.forwarded += len(out)
        return out

    def run(self, max_iterations: int | None = None) -> None:
        """Main loop skeleton (single-threaded placeholder)."""
        self._running = True
        iterations = 0
        with self.backend:
            while self._running:
                for frame in self.backend.recv_burst():
                    try:
                        self.backend.send_burst(self.process_one(frame))
                    except Exception:
                        self.counters.errors += 1
                        log.exception("pipeline error; wire kept intact")
                iterations += 1
                if max_iterations is not None and iterations >= max_iterations:
                    break

    def stop(self) -> None:
        self._running = False
