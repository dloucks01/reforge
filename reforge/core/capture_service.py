"""Threaded capture service.

Runs a CaptureBackend on a background thread and pushes captured frames into a
thread-safe queue. The GUI drains the queue on the UI thread (via a timer), so
Qt is never touched from the capture thread and the UI never blocks at high pps.

Also usable headless: `drain()` returns whatever has been captured so far.
"""

from __future__ import annotations

import logging
import threading
import time
from queue import Empty, Queue

from reforge.capture.base import CaptureBackend, Frame

log = logging.getLogger("reforge.capture_service")


class CaptureService:
    def __init__(self, backend: CaptureBackend, max_queue: int = 100_000):
        self.backend = backend
        self.queue: "Queue[tuple[float, Frame]]" = Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.dropped = 0
        self.captured = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-capture", daemon=True)
        self._thread.start()
        log.info("capture started on backend %s", self.backend.caps.name)

    def _loop(self) -> None:
        try:
            self.backend.open()
            while self._running.is_set():
                frames = self.backend.recv_burst()
                if not frames:
                    # Offline pcap backends exhaust; stop cleanly.
                    if getattr(self.backend, "exhausted", False):
                        break
                    continue
                for f in frames:
                    ts = float(f.meta.get("ts", time.time()))
                    try:
                        self.queue.put_nowait((ts, f))
                        self.captured += 1
                    except Exception:
                        self.dropped += 1  # backpressure: count, never block the wire
        except Exception:
            log.exception("capture loop error")
        finally:
            self.backend.close()
            self._running.clear()

    def drain(self, max_items: int = 5000) -> list[tuple[float, Frame]]:
        """Pull up to max_items captured frames (non-blocking)."""
        out: list[tuple[float, Frame]] = []
        for _ in range(max_items):
            try:
                out.append(self.queue.get_nowait())
            except Empty:
                break
        return out

    @property
    def running(self) -> bool:
        return self._running.is_set()

    def stop(self, join_timeout: float = 2.0) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=join_timeout)
            self._thread = None
        log.info("capture stopped (%d captured, %d dropped)", self.captured, self.dropped)
