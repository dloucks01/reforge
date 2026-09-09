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
                 tap: bool = True, max_queue: int = 100_000,
                 intercept=None, armed: bool = True, seq_fixup: bool = False,
                 checksum_fixup: bool = False, flow_rewrite: bool = False):
        self.if_a = if_a
        self.if_b = if_b
        self.engine = engine or RuleEngine([])
        self.port_factory = port_factory
        self.fail_open = fail_open
        self.tap = tap
        self.intercept = intercept       # optional InterceptQueue
        self.armed = armed               # False = pure pass-through (safe)
        self.checksum_fixup = checksum_fixup  # recompute checksums on every forward
        self.counters = BridgeCounters()
        # flow_rewrite implies seq fix-ups, position-aware (R3)
        self.set_seq_fixup(seq_fixup or flow_rewrite, position_aware=flow_rewrite)

        self._queue: Queue[tuple[float, Frame]] = Queue(maxsize=max_queue)
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self._ready = threading.Event()
        self._heartbeat = time.monotonic()

        # Loop suppression: L2 listen sockets (ETH_P_ALL) also see the frames we
        # transmit, so a re-injected frame would be re-captured and forwarded
        # forever. We remember recently-sent bytes briefly and skip their echo.
        self._sent: dict[bytes, float] = {}
        self._suppress_ttl = 0.5
        # An interactive HOLD is resolved on the GUI thread, whose release closure
        # sends on the same L2 socket as the loop thread and touches _sent + the
        # counters. Serialize every transmit + shared-state mutation so the two
        # threads can't interleave a send (wire corruption) or race the dict.
        self._io_lock = threading.RLock()

    def set_seq_fixup(self, on: bool, position_aware: bool = False) -> None:
        """Enable/disable stateful TCP seq/ack fix-ups (resets flow state).

        position_aware=True uses the R3 FlowRewriter (shifts each segment only by
        edits before it); otherwise the simpler cumulative TcpSeqFixer.
        """
        if not on:
            self.seq_fixer = None
        elif position_aware:
            from reforge.core.flowrewrite import FlowRewriter

            self.seq_fixer = FlowRewriter()
        else:
            from reforge.core.tcpflow import TcpSeqFixer

            self.seq_fixer = TcpSeqFixer()

    @property
    def seq_fixup(self) -> bool:
        return self.seq_fixer is not None

    # ---- per-frame logic ----------------------------------------------------
    def _bump_dir(self, ingress: str, n: int) -> None:
        if ingress == self.if_a:
            self.counters.a_to_b += n
        else:
            self.counters.b_to_a += n

    def _forward(self, ingress: str, data: bytes, send_peer) -> None:
        """Core per-frame handling: engine → forward/drop/hold via send_peer."""
        self.counters.captured += 1
        self._observe(ingress, data)

        if not self.armed:                      # pass-through (safe mode)
            self._emit(send_peer, data)
            self.counters.forwarded += 1
            self._bump_dir(ingress, 1)
            return

        try:
            res = apply_engine(self.engine, data, ingress=ingress, link="ether",
                               seq_fixer=self.seq_fixer,
                               recompute_checksums=self.checksum_fixup)
        except Exception:
            self.counters.errors += 1
            log.exception("engine error; forwarding original frame")
            self._emit(send_peer, data)
            self.counters.forwarded += 1
            return

        if res.disposition is Disposition.DROP:
            self.counters.dropped += 1
            return

        if res.disposition is Disposition.HOLD:
            if self.intercept is not None:
                self._park(ingress, data, send_peer)
                return
            self.counters.held += 1
            # no interception queue attached: pass through
            self._emit(send_peer, data)
            self.counters.forwarded += 1
            self._bump_dir(ingress, 1)
            return

        if res.delay_s:
            self._sleep_delay(res.delay_s)

        out = res.out if res.out is not None else data
        # Ordering: if an earlier packet of this flow is held for interception,
        # this forward must queue behind it so it never overtakes the edited one.
        if self.intercept is not None:
            fk = self._flow_key(ingress, data)
            if self.intercept.passthrough(ingress, out,
                                          self._egress_release(ingress, send_peer, data), fk):
                if res.modified:
                    self.counters.modified += 1
                for extra in res.extra:
                    self.intercept.passthrough(ingress, extra,
                                               self._inject_release(ingress, send_peer), fk) \
                        or self._send_injected(ingress, send_peer, extra)
                return
        self._emit(send_peer, out)
        self.counters.forwarded += 1
        self._bump_dir(ingress, 1)
        if res.modified:
            self.counters.modified += 1
        for extra in res.extra:
            self._send_injected(ingress, send_peer, extra)

    def _flow_key(self, ingress: str, data: bytes):
        """A per-direction flow identity for in-order interception release.

        The two directions of a connection have swapped addresses/ports and arrive
        on different ports, so each direction is ordered independently. Falls back
        to L2 for non-IP frames. Returns a hashable key (never raises)."""
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6
            from scapy.layers.l2 import Ether

            eth = Ether(data)
            ip = eth.getlayer(IP) or eth.getlayer(IPv6)
            if ip is not None:
                l4 = ip.getlayer(TCP) or ip.getlayer(UDP)
                if l4 is not None:
                    return (ingress, ip.src, int(l4.sport), ip.dst, int(l4.dport),
                            l4.__class__.__name__)
                return (ingress, ip.src, ip.dst, int(getattr(ip, "proto", getattr(ip, "nh", 0))))
            return (ingress, eth.src, eth.dst, int(eth.type))
        except Exception:
            return (ingress, bytes(data[:14]))     # last resort: L2 header bytes

    def _egress_release(self, ingress: str, send_peer, orig: bytes):
        """Release closure for a forwarded/held packet: send + count."""
        def release(out_bytes, *, _ingress=ingress, _send=send_peer, _orig=orig):
            if out_bytes is None:
                self.counters.dropped += 1
                return
            self._emit(_send, out_bytes)
            self.counters.forwarded += 1
            self._bump_dir(_ingress, 1)
            if out_bytes != _orig:
                self.counters.modified += 1
        return release

    def _inject_release(self, ingress: str, send_peer):
        """Release closure for an injected/duplicated extra packet."""
        def release(out_bytes, *, _ingress=ingress, _send=send_peer):
            if out_bytes is None:
                return
            self._emit(_send, out_bytes)
            self.counters.injected += 1
            self.counters.forwarded += 1
            self._bump_dir(_ingress, 1)
        return release

    def _send_injected(self, ingress: str, send_peer, extra: bytes) -> None:
        self._emit(send_peer, extra)
        self.counters.injected += 1
        self.counters.forwarded += 1
        self._bump_dir(ingress, 1)

    def _park(self, ingress: str, data: bytes, send_peer) -> None:
        """Divert a held packet to the interception queue (non-blocking).

        If the queue is at capacity, the packet is not held: it is forwarded (in
        flow order) or dropped per the queue's overflow policy, so a high-volume
        stream never fully piles up in the queue."""
        fk = self._flow_key(ingress, data)
        hp = self.intercept.hold(ingress, data,
                                 self._egress_release(ingress, send_peer, data), flow_key=fk)
        if hp is not None:
            self.counters.held += 1
            return
        # overflow: at capacity -> handle without holding, preserving flow order
        if self.intercept.overflow == "drop":
            self.counters.dropped += 1
            return
        if self.intercept.passthrough(ingress, data,
                                      self._egress_release(ingress, send_peer, data), fk):
            return                              # queued behind an earlier held packet
        self._emit(send_peer, data)
        self.counters.forwarded += 1
        self._bump_dir(ingress, 1)

    def process_frame(self, ingress: str, data: bytes) -> list[bytes]:
        """Pure form for tests/headless: returns bytes to send on the peer port.

        Uses the same core logic with a collector as the transmit function and
        no interception queue (HOLD falls through to pass-through).
        """
        sends: list[bytes] = []
        saved = self.intercept
        self.intercept = None
        try:
            self._forward(ingress, data, sends.append)
        finally:
            self.intercept = saved
        return sends

    def _emit(self, send_peer, data: bytes) -> None:
        """Transmit + record the send under the I/O lock, so the loop thread and a
        GUI-thread interception release never interleave on the socket or _sent."""
        with self._io_lock:
            send_peer(data)
            self._sent[data] = time.monotonic() + self._suppress_ttl

    def _remember_sent(self, data: bytes) -> None:
        with self._io_lock:
            self._sent[data] = time.monotonic() + self._suppress_ttl

    def _is_own_echo(self, data: bytes) -> bool:
        now = time.monotonic()
        with self._io_lock:
            expiry = self._sent.get(data)
            if expiry is not None and expiry > now:
                del self._sent[data]  # consume the one echo we expect
                return True
            # opportunistic prune of stale entries
            if len(self._sent) > 4096:
                self._sent = {k: v for k, v in self._sent.items() if v > now}
        return False

    def _sleep_delay(self, delay_s: float) -> None:
        """Apply a rule `delay` without tripping the watchdog.

        The delay blocks this frame inline (the honest cost of an inline delay),
        but we refresh the heartbeat in small chunks so the watchdog does not read
        the pause as a stalled bridge and fail the wire open. Headless
        (process_frame, loop not running) returns immediately so tests never sleep.
        """
        if not self._running.is_set():
            return
        end = time.monotonic() + delay_s
        while self._running.is_set():
            remaining = end - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(remaining, 0.2))
            self._heartbeat = time.monotonic()

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
                    self._forward(iface, data, dst.send)
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
