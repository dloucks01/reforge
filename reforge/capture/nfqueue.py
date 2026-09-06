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
from dataclasses import dataclass, field

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
    def __init__(self, engine: RuleEngine, queue_num: int = 1):
        self.engine = engine
        self.queue_num = queue_num
        self.stats = NfqStats()
        self._nfq = None

    def process(self, nfq_packet) -> None:
        """Handle one NFQUEUE packet object.

        The object must provide get_payload(), and for verdicts:
        set_payload(bytes), accept(), drop().
        """
        self.stats.seen += 1
        try:
            raw = nfq_packet.get_payload()
            res = apply_engine(self.engine, raw, link="ip")
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
            # Interactive intercept queue is Phase 4; for now pass through.
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

    def run(self) -> None:  # pragma: no cover (needs root + kernel queue)
        """Bind the queue and block, dispatching packets to process()."""
        from netfilterqueue import NetfilterQueue

        self._nfq = NetfilterQueue()
        self._nfq.bind(self.queue_num, lambda p: self.process(p))
        log.info("bound NFQUEUE %d; install an nft/iptables rule to feed it", self.queue_num)
        try:
            self._nfq.run()
        finally:
            self._nfq.unbind()


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
