"""Idempotent interface setup/teardown with automatic revert.

This is where the inline-tool footguns from PLAN.md section 6 are neutralized:
disable NIC offloads, put NICs in promisc + allmulti, remove IPs, and suppress
host-stack interference. Every change records how to undo it, so teardown (or a
crash-recovery revert) leaves the host exactly as it was found.

Phase 0: commands are assembled and logged; execution is gated behind
`apply=True` and normally runs inside the privileged helper. The revert journal
is the important part of the design.
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("reforge.netconfig")

# Offloads that must be OFF so captured/forwarded bytes match the wire.
OFFLOADS = ["tso", "gso", "gro", "lro", "rx", "tx", "sg", "rxvlan", "txvlan"]


@dataclass
class RevertJournal:
    """Records undo commands in reverse order for exact restoration."""

    entries: list[list[str]] = field(default_factory=list)

    def record(self, undo_cmd: list[str]) -> None:
        self.entries.append(undo_cmd)

    def revert(self, run) -> None:
        for cmd in reversed(self.entries):
            try:
                run(cmd)
            except Exception:
                log.exception("revert step failed: %s", " ".join(cmd))
        self.entries.clear()


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    log.debug("run: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def prepare_capture_iface(iface: str, journal: RevertJournal, apply: bool = False) -> list[list[str]]:
    """Return (and optionally execute) the commands to make `iface` capture-ready.

    - disable offloads (record current state for revert)
    - up + promisc + allmulti
    - flush IPv4/IPv6 addresses, disable IPv6 autoconf
    """
    planned: list[list[str]] = []

    for feat in OFFLOADS:
        planned.append(["ethtool", "-K", iface, feat, "off"])
        journal.record(["ethtool", "-K", iface, feat, "on"])

    planned += [
        ["ip", "link", "set", iface, "up"],
        ["ip", "link", "set", iface, "promisc", "on"],
        ["ip", "link", "set", iface, "allmulticast", "on"],
        ["ip", "addr", "flush", "dev", iface],
        ["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
    ]
    journal.record(["ip", "link", "set", iface, "promisc", "off"])
    journal.record(["ip", "link", "set", iface, "allmulticast", "off"])
    journal.record(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=0"])

    if apply:
        for cmd in planned:
            _run(cmd)
    else:
        for cmd in planned:
            log.info("[plan] %s", " ".join(cmd))
    return planned


def suppress_host_stack(iface: str, journal: RevertJournal, apply: bool = False) -> list[list[str]]:
    """Stop the host kernel from answering traffic it observes inline.

    Drops host-originated RST/ARP on the capture interface so the tool doesn't
    fight its own kernel (PLAN.md section 6). Uses nftables.
    """
    planned = [
        ["nft", "add", "table", "inet", "reforge"],
        ["nft", "add", "chain", "inet", "reforge", "out",
         "{ type filter hook output priority 0 ; }"],
        ["nft", "add", "rule", "inet", "reforge", "out",
         "oifname", iface, "tcp", "flags", "rst", "drop"],
        ["nft", "add", "rule", "inet", "reforge", "out",
         "oifname", iface, "arp", "drop"],
    ]
    journal.record(["nft", "delete", "table", "inet", "reforge"])
    if apply:
        for cmd in planned:
            _run(cmd)
    else:
        for cmd in planned:
            log.info("[plan] %s", " ".join(cmd))
    return planned
