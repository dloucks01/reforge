"""Watchdog for the userspace bridge.

A userspace bridge is a single point of failure on the wire: if the forward loop
stalls or the process dies, traffic stops. The watchdog polls a heartbeat age
callback; if the loop hasn't ticked within `timeout`, it trips once and invokes
`on_trip`, which enacts the fail policy:

- fail-open  -> hand the link back to a kernel bridge (or a bypass NIC) so
               traffic keeps flowing unmanipulated.
- fail-closed -> drop the links so nothing passes.

The decision logic (`should_trip`) is separated from the thread so it is
testable with a synthetic clock.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable

log = logging.getLogger("reforge.watchdog")


class Watchdog:
    def __init__(self, heartbeat_age: Callable[[], float], timeout: float,
                 on_trip: Callable[[], None], poll_interval: float = 0.5):
        self._heartbeat_age = heartbeat_age
        self.timeout = timeout
        self._on_trip = on_trip
        self.poll_interval = poll_interval
        self.tripped = False
        self._thread: threading.Thread | None = None
        self._running = threading.Event()

    def should_trip(self, age: float | None = None) -> bool:
        """Pure decision: has the loop been silent past the timeout?"""
        age = self._heartbeat_age() if age is None else age
        return (not self.tripped) and age > self.timeout

    def _check_once(self) -> None:
        if self.should_trip():
            self.tripped = True
            log.warning("watchdog tripped (loop silent > %.1fs) — enacting fail policy",
                        self.timeout)
            try:
                self._on_trip()
            except Exception:
                log.exception("fail policy enactment failed")

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-watchdog", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while self._running.is_set():
            self._check_once()
            # Event.wait doubles as an interruptible sleep for stop().
            self._running.wait(self.poll_interval)

    def stop(self) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None

    def reset(self) -> None:
        self.tripped = False
