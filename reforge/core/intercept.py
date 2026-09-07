"""Interactive interception queue with in-order release.

When a rule's verdict is HOLD, the inline path parks the packet here instead of
forwarding it, and continues processing other traffic (non-blocking hold, so the
wire never stalls and the watchdog stays happy). The operator then inspects and
edits the held packet and resolves it: forward as-is, forward modified, or drop.

Ordering: many protocols require bytes to leave in the same order they arrived.
If a packet of a flow is held, any *later* packet of the same flow must not
overtake it. Each held/forwarded packet is placed on a per-flow FIFO; a flow's
packets are released strictly head-first, and a still-held (un-resolved) packet
blocks everything behind it in its flow until the operator resolves it. Packets
of other flows are unaffected. Pass `flow_key=None` (or ordered=False) to opt a
packet out of ordering (it then blocks nothing and releases as soon as resolved).

The queue is transport-agnostic: the caller supplies an `on_release(bytes|None)`
closure that actually transmits (bytes) or drops (None) on the right egress, so
this module knows nothing about bridges or sockets and is easy to test.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from queue import Empty, Queue


@dataclass
class HeldPacket:
    id: int
    ingress: str
    data: bytes
    ts: float
    _release: Callable[[bytes | None], None]
    flow_key: object = None
    operator: bool = True                       # True = shown in the GUI queue
    outcome: tuple | None = None             # ("send", bytes) | ("drop", None)
    deadline: float | None = None            # auto-release time (None = never)
    kind: str = "packet"                     # "packet" (raw frame) | "message" (HTTP)
    meta: dict | None = None                 # display hints (e.g. summary line)

    @property
    def resolved(self) -> bool:
        return self.outcome is not None


class InterceptQueue:
    """Interactive hold queue with in-order release and volume safeguards.

    max_held  : cap on packets held for the operator at once (0 = unlimited).
                Once full, further matches are auto-resolved per `overflow`
                instead of held, so a busy stream never drowns the queue. This
                doubles as the 'step through N at a time' control.
    auto_release_s : a held packet not resolved within this many seconds is
                auto-resolved per `overflow` (0 = never), so a stalled flow does
                not block the wire or grow memory unbounded.
    overflow  : 'forward' | 'drop' — what auto-resolution does.
    """

    def __init__(self, ordered: bool = True, max_held: int = 0,
                 auto_release_s: float = 0.0, overflow: str = "forward"):
        self.ordered = ordered
        self.max_held = max_held
        self.auto_release_s = auto_release_s
        self.overflow = overflow if overflow in ("forward", "drop") else "forward"
        self._pending: dict[int, HeldPacket] = {}   # operator-visible, unresolved holds
        self._flows: dict[object, list[HeldPacket]] = {}  # per-flow FIFO (hold + passthrough)
        self._lock = threading.Lock()
        self._next_id = 0
        self._new: Queue[int] = Queue()
        self.stats = {"held": 0, "forwarded": 0, "modified": 0, "dropped": 0,
                      "auto_released": 0, "overflowed": 0}

    # ---- ingress from the inline path --------------------------------------
    def hold(self, ingress: str, data: bytes,
             on_release: Callable[[bytes | None], None],
             flow_key: object = None, kind: str = "packet",
             meta: dict | None = None) -> HeldPacket | None:
        """Park a packet/message for the operator. Blocks its flow until resolved.

        Returns the HeldPacket, or None if the queue is at capacity — in which
        case the caller must forward/drop the item itself (per overflow), so a
        high-volume stream is never fully absorbed into the queue.
        """
        self.reap()                             # sweep timed-out holds first
        with self._lock:
            if self.max_held and len(self._pending) >= self.max_held:
                self.stats["overflowed"] += 1
                return None                     # at capacity: caller handles it
            self._next_id += 1
            key = flow_key if (self.ordered and flow_key is not None) else object()
            deadline = (time.time() + self.auto_release_s) if self.auto_release_s else None
            hp = HeldPacket(self._next_id, ingress, bytes(data), time.time(),
                            on_release, flow_key=key, operator=True, deadline=deadline,
                            kind=kind, meta=meta)
            self._pending[hp.id] = hp
            self._flows.setdefault(key, []).append(hp)
            self.stats["held"] += 1
        self._new.put(hp.id)
        return hp

    def reap(self) -> int:
        """Auto-resolve holds past their deadline (keeps the wire from stalling)."""
        if not self.auto_release_s:
            return 0
        now = time.time()
        ready: list[HeldPacket] = []
        expired = 0
        with self._lock:
            due = [hp for hp in self._pending.values()
                   if hp.deadline is not None and hp.deadline <= now]
            for hp in due:
                self._pending.pop(hp.id, None)
                hp.outcome = ("send", hp.data) if self.overflow == "forward" else ("drop", None)
                self.stats["auto_released"] += 1
                expired += 1
                ready += self._drain_flow_locked(hp.flow_key)
        for h in ready:
            self._deliver(h)
        return expired

    def passthrough(self, ingress: str, data: bytes,
                    on_release: Callable[[bytes | None], None],
                    flow_key: object) -> bool:
        """Queue a to-be-forwarded packet behind earlier held packets of its flow.

        Returns True if it was queued (the caller must NOT transmit — it will be
        released in order once the flow head clears). Returns False if the flow
        has nothing pending, so the caller should transmit immediately.
        """
        if not self.ordered or flow_key is None:
            return False
        with self._lock:
            q = self._flows.get(flow_key)
            if not q:
                return False                    # flow clear -> caller sends now
            self._next_id += 1
            hp = HeldPacket(self._next_id, ingress, bytes(data), time.time(),
                            on_release, flow_key=flow_key, operator=False,
                            outcome=("send", bytes(data)))  # pre-resolved forward
            q.append(hp)
        return True

    # ---- operator actions ---------------------------------------------------
    def resolve(self, pid: int, action: str, new_bytes: bytes | None = None) -> bool:
        """action: 'forward' | 'modify' | 'drop'. Returns True if it was pending.

        Releases this packet and any now-contiguous packets behind it, in order.
        """
        with self._lock:
            hp = self._pending.pop(pid, None)
            if hp is None or hp.resolved:
                return False
            if action == "drop":
                hp.outcome = ("drop", None)
                self.stats["dropped"] += 1
            elif action == "modify":
                hp.outcome = ("send", new_bytes if new_bytes is not None else hp.data)
                self.stats["modified"] += 1
            else:  # forward as-is
                hp.outcome = ("send", hp.data)
                self.stats["forwarded"] += 1
            ready = self._drain_flow_locked(hp.flow_key)
        for h in ready:                          # release outside the lock (does I/O)
            self._deliver(h)
        return True

    def release_all(self, action: str = "forward") -> int:
        """Resolve every operator-held packet (used by the kill-switch)."""
        n = 0
        for hp in self.pending():
            if self.resolve(hp.id, action):
                n += 1
        return n

    # ---- internal -----------------------------------------------------------
    def _drain_flow_locked(self, key: object) -> list[HeldPacket]:
        """Pop and return the run of resolved packets at the head of a flow."""
        ready: list[HeldPacket] = []
        q = self._flows.get(key)
        if q is None:
            return ready
        while q and q[0].resolved:
            ready.append(q.pop(0))
        if not q:
            self._flows.pop(key, None)
        return ready

    @staticmethod
    def _deliver(hp: HeldPacket) -> None:
        kind, payload = hp.outcome
        hp._release(payload if kind == "send" else None)

    # ---- GUI-facing views ---------------------------------------------------
    def pending(self) -> list[HeldPacket]:
        with self._lock:
            return sorted(self._pending.values(), key=lambda h: h.id)

    def count(self) -> int:
        with self._lock:
            return len(self._pending)

    def get(self, pid: int) -> HeldPacket | None:
        with self._lock:
            return self._pending.get(pid)

    def drain_new(self) -> list[int]:
        """IDs newly held since the last call (for the GUI to pick up)."""
        out: list[int] = []
        while True:
            try:
                out.append(self._new.get_nowait())
            except Empty:
                break
        return out
