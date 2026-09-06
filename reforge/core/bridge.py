"""Userspace transparent bridge — the primary inline mode.

Two NICs, no IPs, both promiscuous. Frames captured on one port run through the
rule engine and are re-injected on the peer port (and symmetrically), so we own
forwarding and can rewrite anything at L2-L7, drop, delay, duplicate, or inject.

The per-frame logic lives in `process_frame()` (pure: bytes in, bytes-to-send
out, counters updated) so it is fully testable with fake ports — no root, no
NICs. The threaded loop just does select() + recv/send around it.

Availability note: in a userspace bridge, if this process dies the wire goes
dark. A Watchdog (core/watchdog.py) enforces a fail-open/closed policy.
"""

from __future__ import annotations

import logging
import select
import threading
import time
from dataclasses import dataclass
from queue import Empty, Full, Queue

from reforge.capture.base import Frame
from reforge.core.apply import apply_engine
from reforge.rules.base import Disposition
from reforge.rules.engine import RuleEngine

log = logging.getLogger("reforge.bridge")


@dataclass
class BridgeCounters:
    captured: int = 0
    forwarded: int = 0
    a_to_b: int = 0
    b_to_a: int = 0
    dropped: int = 0
    modified: int = 0
    injected: int = 0
    held: int = 0
    errors: int = 0
    tap_dropped: int = 0

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class ScapyPort:
    """A bidirectional L2 port (listen + send) on one interface, via Scapy."""

    def __init__(self, iface: str):
        # Import from scapy.all so the arch layer initializes conf.L2listen /
        # conf.L2socket (they are None until that init runs).
        from scapy.all import conf

        self.iface = iface
        self._listen = conf.L2listen(iface=iface)
        self._send = conf.L2socket(iface=iface)

    def fileno(self) -> int:
        return self._listen.fileno()

    def recv(self) -> bytes | None:
        pkt = self._listen.recv()
        return bytes(pkt) if pkt is not None else None

    def send(self, data: bytes) -> None:
        from scapy.layers.l2 import Ether

        self._send.send(Ether(data))

    def close(self) -> None:
        for s in (self._listen, self._send):
            try:
                s.close()
            except Exception:
                pass


class UserspaceBridge:
    """Bidirectional inline bridge between two interfaces through the engine."""

    def __init__(self, if_a: str, if_b: str, engine: RuleEngine | None = None, *,
                 port_factory=ScapyPort, fail_open: bool = True,
                 tap: bool = True, max_queue: int = 100_000):
        self.if_a = if_a
        self.if_b = if_b
        self.engine = engine or RuleEngine([])
        self.port_factory = port_factory
        self.fail_open = fail_open
        self.tap = tap
        self.counters = BridgeCounters()

        self._queue: "Queue[tuple[float, Frame]]" = Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._ready = threading.Event()
        self._heartbeat = time.monotonic()

        # Loop suppression: L2 listen sockets (ETH_P_ALL) also see the frames we
        # transmit, so a re-injected frame would be re-captured and forwarded
        # forever. We remember recently-sent bytes briefly and skip their echo.
        self._sent: dict[bytes, float] = {}
        self._suppress_ttl = 0.5

    # ---- per-frame logic (pure + testable) ---------------------------------
    def process_frame(self, ingress: str, data: bytes) -> list[bytes]:
        """Return the bytes to transmit on the peer port for one input frame."""
        self.counters.captured += 1
        self._observe(ingress, data)
        try:
            res = apply_engine(self.engine, data, ingress=ingress, link="ether")
        except Exception:
            self.counters.errors += 1
            log.exception("engine error; forwarding original frame")
            return [data]

        if res.disposition is Disposition.DROP:
            self.counters.dropped += 1
            return []
        if res.disposition is Disposition.HOLD:
            # Interactive intercept queue is Phase 4; pass through for now.
            self.counters.held += 1

        if res.delay_s:
            time.sleep(res.delay_s)

        out = res.out if res.out is not None else data
        sends = [out]
        if res.modified:
            self.counters.modified += 1
        for extra in res.extra:
            sends.append(extra)
            self.counters.injected += 1

        self.counters.forwarded += len(sends)
        if ingress == self.if_a:
            self.counters.a_to_b += len(sends)
        else:
            self.counters.b_to_a += len(sends)
        return sends

    def _remember_sent(self, data: bytes) -> None:
        self._sent[data] = time.monotonic() + self._suppress_ttl

    def _is_own_echo(self, data: bytes) -> bool:
        now = time.monotonic()
        expiry = self._sent.get(data)
        if expiry is not None and expiry > now:
            del self._sent[data]  # consume the one echo we expect
            return True
        # opportunistic prune of stale entries
        if len(self._sent) > 4096:
            self._sent = {k: v for k, v in self._sent.items() if v > now}
        return False

    def _observe(self, ingress: str, data: bytes) -> None:
        if not self.tap:
            return
        try:
            self._queue.put_nowait((time.time(), Frame(data=data, ingress=ingress)))
        except Full:
            self.counters.tap_dropped += 1

    # ---- lifecycle ----------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-bridge", daemon=True)
        self._thread.start()
        log.info("bridge started: %s <-> %s (fail-%s)", self.if_a, self.if_b,
                 "open" if self.fail_open else "closed")

    def _loop(self) -> None:
        try:
            port_a = self.port_factory(self.if_a)
            port_b = self.port_factory(self.if_b)
        except Exception:
            log.exception("could not open bridge ports")
            self._running.clear()
            return

        peers = {
            port_a.fileno(): (port_a, port_b, self.if_a),
            port_b.fileno(): (port_b, port_a, self.if_b),
        }
        # Ports are open and the loop is about to tick: mark ready and reset the
        # heartbeat so the watchdog doesn't count slow startup as a stall.
        self._heartbeat = time.monotonic()
        self._ready.set()
        try:
            while self._running.is_set():
                self._heartbeat = time.monotonic()
                readable, _, _ = select.select([port_a, port_b], [], [], 0.5)
                for p in readable:
                    src, dst, iface = peers[p.fileno()]
                    data = src.recv()
                    if not data:
                        continue
                    if self._is_own_echo(data):
                        continue  # a frame we just transmitted; don't loop it
                    for out in self.process_frame(iface, data):
                        dst.send(out)
                        self._remember_sent(out)
        except Exception:
            log.exception("bridge loop error")
        finally:
            port_a.close()
            port_b.close()
            self._running.clear()

    def drain(self, max_items: int = 5000) -> list[tuple[float, Frame]]:
        out: list[tuple[float, Frame]] = []
        for _ in range(max_items):
            try:
                out.append(self._queue.get_nowait())
            except Empty:
                break
        return out

    @property
    def running(self) -> bool:
        return self._running.is_set()

    def wait_ready(self, timeout: float = 8.0) -> bool:
        """Block until ports are open and the loop is ticking (or timeout)."""
        return self._ready.wait(timeout) and self._running.is_set()

    def heartbeat_age(self) -> float:
        """Seconds since the forward loop last ticked (for the watchdog)."""
        return time.monotonic() - self._heartbeat

    def stop(self, join_timeout: float = 2.0) -> None:
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=join_timeout)
            self._thread = None
        log.info("bridge stopped: %s", self.counters.as_dict())
