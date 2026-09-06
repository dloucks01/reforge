"""Interactive interception queue.

When a rule's verdict is HOLD, the inline path parks the packet here instead of
forwarding it, and continues processing other traffic (non-blocking hold, so the
wire never stalls and the watchdog stays happy). The operator then inspects and
edits the held packet and resolves it: forward as-is, forward modified, or drop.

The queue is transport-agnostic: the caller supplies an `on_release(bytes|None)`
closure that actually transmits (bytes) or drops (None) on the right egress, so
this module knows nothing about bridges or sockets and is easy to test.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from queue import Empty, Queue
from typing import Callable, Optional


@dataclass
class HeldPacket:
    id: int
    ingress: str
    data: bytes
    ts: float
    _release: Callable[[Optional[bytes]], None]
    resolved: bool = False


class InterceptQueue:
    def __init__(self):
        self._pending: dict[int, HeldPacket] = {}
        self._lock = threading.Lock()
        self._next_id = 0
        self._new: "Queue[int]" = Queue()
        self.stats = {"held": 0, "forwarded": 0, "modified": 0, "dropped": 0}

    def hold(self, ingress: str, data: bytes,
             on_release: Callable[[Optional[bytes]], None]) -> HeldPacket:
        with self._lock:
            self._next_id += 1
            hp = HeldPacket(self._next_id, ingress, bytes(data), time.time(), on_release)
            self._pending[hp.id] = hp
            self.stats["held"] += 1
        self._new.put(hp.id)
        return hp

    def pending(self) -> list[HeldPacket]:
        with self._lock:
            return sorted(self._pending.values(), key=lambda h: h.id)

    def count(self) -> int:
        with self._lock:
            return len(self._pending)

    def get(self, pid: int) -> HeldPacket | None:
        with self._lock:
            return self._pending.get(pid)

    def resolve(self, pid: int, action: str, new_bytes: bytes | None = None) -> bool:
        """action: 'forward' | 'modify' | 'drop'. Returns True if it was pending."""
        with self._lock:
            hp = self._pending.pop(pid, None)
        if hp is None or hp.resolved:
            return False
        hp.resolved = True
        if action == "drop":
            hp._release(None)
            self.stats["dropped"] += 1
        elif action == "modify":
            hp._release(new_bytes if new_bytes is not None else hp.data)
            self.stats["modified"] += 1
        else:  # forward as-is
            hp._release(hp.data)
            self.stats["forwarded"] += 1
        return True

    def release_all(self, action: str = "forward") -> int:
        """Resolve every pending packet (used by the kill-switch)."""
        n = 0
        for hp in self.pending():
            if self.resolve(hp.id, action):
                n += 1
        return n

    def drain_new(self) -> list[int]:
        """IDs newly held since the last call (for the GUI to pick up)."""
        out: list[int] = []
        while True:
            try:
                out.append(self._new.get_nowait())
            except Empty:
                break
        return out
