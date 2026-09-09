"""NFQUEUE inline runner (kernel-assisted L3-L7 manipulation).

The host is a routed hop (or a bridge with br_netfilter); an nftables/iptables
rule diverts packets to a userspace queue. For each packet we run the rule
engine and issue an NFQUEUE verdict: accept (optionally with a rewritten
payload), drop, or (later) hold.

NFQUEUE hands us IP payloads (no L2), so packets are dissected with link="ip".
`process()` is split out from the netfilterqueue callback so it can be tested
with a fake packet object (no root, no kernel).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from reforge.core.apply import apply_engine
from reforge.rules.base import Disposition
from reforge.rules.engine import RuleEngine

log = logging.getLogger("reforge.nfqueue")


@dataclass
class NfqStats:
    seen: int = 0
    accepted: int = 0
    modified: int = 0
    dropped: int = 0
    held: int = 0
    errors: int = 0

    def as_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


class NfqueueRunner:
    def __init__(self, engine: RuleEngine, queue_num: int = 1, intercept=None,
                 seq_fixer=None):
        self.engine = engine
        self.queue_num = queue_num
        self.intercept = intercept   # optional InterceptQueue for interactive HOLD
        self.seq_fixer = seq_fixer   # keeps TCP flows in sync after length-changing edits
        self.stats = NfqStats()
        self._nfq = None
        self._running = False

    @staticmethod
    def _flow_key(raw: bytes):
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.inet6 import IPv6

            ip = (IPv6 if raw and (raw[0] >> 4) == 6 else IP)(raw)
            l4 = ip.getlayer(TCP) or ip.getlayer(UDP)
            if l4 is not None:
                return (ip.src, int(l4.sport), ip.dst, int(l4.dport), l4.__class__.__name__)
            return (getattr(ip, "src", ""), getattr(ip, "dst", ""))
        except Exception:
            return None

    def process(self, nfq_packet) -> None:
        """Handle one NFQUEUE packet object.

        The object must provide get_payload(), and for verdicts:
        set_payload(bytes), accept(), drop(). Verdicts may be issued later (a
        held packet's verdict is deferred until the operator resolves it).
        """
        self.stats.seen += 1
        try:
            raw = nfq_packet.get_payload()
            res = apply_engine(self.engine, raw, link="ip", seq_fixer=self.seq_fixer)
        except Exception:
            self.stats.errors += 1
            log.exception("engine error; accepting packet unchanged")
            nfq_packet.accept()
            return

        if res.disposition is Disposition.DROP:
            self.stats.dropped += 1
            nfq_packet.drop()
            return

        if res.disposition is Disposition.HOLD:
            if self.intercept is not None and self._park(nfq_packet, raw):
                return
            self.stats.held += 1
            nfq_packet.accept()
            return

        if res.delay_s:
            time.sleep(res.delay_s)
        if res.modified and res.out is not None:
            nfq_packet.set_payload(res.out)
            self.stats.modified += 1
        self.stats.accepted += 1
        nfq_packet.accept()
        # NB: res.extra (injected/duplicated) needs a raw send socket — Phase 3.

    def _park(self, nfq_packet, raw: bytes) -> bool:
        """Divert a HELD packet to the intercept queue; verdict issued on resolve.

        Returns True if parked, False if the queue is at capacity (caller forwards)."""
        def release(out, *, _pkt=nfq_packet, _orig=raw):
            if out is None:
                self.stats.dropped += 1
                _pkt.drop()
                return
            if out != _orig:
                _pkt.set_payload(out)
                self.stats.modified += 1
            self.stats.accepted += 1
            _pkt.accept()

        hp = self.intercept.hold("nfqueue", raw, release,
                                 flow_key=self._flow_key(raw), link="ip")
        if hp is not None:
            self.stats.held += 1
            return True
        if self.intercept.overflow == "drop":   # at capacity
            self.stats.dropped += 1
            nfq_packet.drop()
            return True
        return False                             # caller accepts unchanged

    def run(self) -> None:  # pragma: no cover (needs root + kernel queue)
        """Bind the queue and dispatch packets until stop(); interruptible."""
        import select
        import socket

        from netfilterqueue import NetfilterQueue

        self._running = True
        self._nfq = NetfilterQueue()
        self._nfq.bind(self.queue_num, lambda p: self.process(p))
        log.info("bound NFQUEUE %d; forwarded packets now manipulable", self.queue_num)
        s = socket.fromfd(self._nfq.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        s.setblocking(False)     # else run_socket() can block on recv after the
                                 # queue drains, and stop() can't interrupt it
        try:
            while self._running:
                r, _, _ = select.select([s], [], [], 0.4)
                if r:
                    try:
                        self._nfq.run_socket(s)
                    except BlockingIOError:
                        pass     # nothing left to read this wake-up
        except Exception:
            log.exception("NFQUEUE loop error")
        finally:
            try:
                self._nfq.unbind()
            except Exception:
                pass
            s.close()
            # drop the NetfilterQueue so its netlink socket is freed now, not at
            # GC — otherwise a quick rebind of the same queue number can fail with
            # "Failed to create queue".
            self._nfq = None

    def stop(self) -> None:
        self._running = False


# --- kernel glue (install/remove the queue rule) ----------------------------
def nft_queue_rules(queue_num: int = 1, chain: str = "forward") -> tuple[list[str], list[str]]:
    """Return (install_cmd, remove_cmd) nft rules to feed a queue.

    Uses a dedicated table so teardown is a single delete. `chain` is typically
    'forward' (routed) or 'prerouting'/'postrouting'.
    """
    hook = {"forward": "forward", "prerouting": "prerouting",
            "postrouting": "postrouting"}.get(chain, "forward")
    prio = 0
    install = [
        ["nft", "add", "table", "inet", "reforge_q"],
        ["nft", "add", "chain", "inet", "reforge_q", chain,
         f"{{ type filter hook {hook} priority {prio} ; }}"],
        ["nft", "add", "rule", "inet", "reforge_q", chain, "counter", "queue", "num",
         str(queue_num)],
    ]
    remove = [["nft", "delete", "table", "inet", "reforge_q"]]
    return install, remove


def nft_forward_queue_rules(queue_num: int = 1,
                            victims: list[str] | None = None) -> tuple[list[list[str]], list[list[str]]]:
    """nft rules to queue FORWARDed packets — optionally only a victim set.

    Pairs with ARP MITM + IP forwarding: the poisoned victims' traffic is routed
    by the kernel and diverted here for rule-engine / interactive manipulation.
    """
    install = [
        ["nft", "add", "table", "inet", "reforge_q"],
        ["nft", "add", "chain", "inet", "reforge_q", "forward",
         "{ type filter hook forward priority 0 ; }"],
    ]
    if victims:
        # nft rejects an IPv6 literal in an `ip saddr` set (and vice-versa), so
        # split the victim set by family and emit `ip`/`ip6` matchers accordingly.
        v4 = [v for v in victims if ":" not in v]
        v6 = [v for v in victims if ":" in v]
        for fam, group in (("ip", v4), ("ip6", v6)):
            if not group:
                continue
            elems = "{ " + ", ".join(group) + " }"
            install.append(["nft", "add", "rule", "inet", "reforge_q", "forward",
                            fam, "saddr", elems, "counter", "queue", "num", str(queue_num)])
            install.append(["nft", "add", "rule", "inet", "reforge_q", "forward",
                            fam, "daddr", elems, "counter", "queue", "num", str(queue_num)])
    else:
        install.append(["nft", "add", "rule", "inet", "reforge_q", "forward",
                        "counter", "queue", "num", str(queue_num)])
    remove = [["nft", "delete", "table", "inet", "reforge_q"]]
    return install, remove
