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
import re
import subprocess
from dataclasses import dataclass, field

log = logging.getLogger("reforge.netconfig")

# Interface names are interpolated into privileged commands. Even though they go
# in as list args (no shell), a flag-like name could be misparsed as an option by
# ethtool/ip. Validate strictly and reject anything flag-like.
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.@:-]{1,64}$")


def _check_iface(iface: str) -> str:
    if not isinstance(iface, str) or iface.startswith("-") or not _IFACE_RE.match(iface):
        raise ValueError(f"invalid interface name: {iface!r}")
    return iface

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
    _check_iface(iface)
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


def prepare_bridge(if_a: str, if_b: str, journal: RevertJournal,
                   apply: bool = False) -> list[list[str]]:
    """Prepare BOTH interfaces for a userspace transparent bridge.

    Each interface: offloads off, promisc + allmulti, no IP; plus host-stack
    suppression so the kernel doesn't answer traffic crossing the bridge. The
    journal captures every undo for a clean revert.
    """
    _check_iface(if_a); _check_iface(if_b)
    planned: list[list[str]] = []
    for iface in (if_a, if_b):
        planned += prepare_capture_iface(iface, journal, apply=apply)
        planned += suppress_host_stack(iface, journal, apply=apply)
    return planned


FAIL_BRIDGE = "reforge-fo0"


def fail_open_commands(if_a: str, if_b: str, journal: RevertJournal,
                       apply: bool = False) -> list[list[str]]:
    """Kernel-bridge fallback so traffic keeps flowing if the app stops.

    Joins both NICs into a plain kernel bridge (unmanipulated pass-through).
    On a bypass-capable NIC this would instead switch the card to Bypass mode.
    """
    _check_iface(if_a); _check_iface(if_b)
    planned = [
        ["ip", "link", "add", "name", FAIL_BRIDGE, "type", "bridge"],
        ["ip", "link", "set", if_a, "master", FAIL_BRIDGE],
        ["ip", "link", "set", if_b, "master", FAIL_BRIDGE],
        ["ip", "link", "set", FAIL_BRIDGE, "up"],
    ]
    journal.record(["ip", "link", "set", if_a, "nomaster"])
    journal.record(["ip", "link", "set", if_b, "nomaster"])
    journal.record(["ip", "link", "del", FAIL_BRIDGE])
    if apply:
        for cmd in planned:
            _run(cmd)
    else:
        for cmd in planned:
            log.info("[plan] %s", " ".join(cmd))
    return planned


def fail_closed_commands(if_a: str, if_b: str, journal: RevertJournal,
                         apply: bool = False) -> list[list[str]]:
    """Drop both links so nothing passes when the app stops."""
    _check_iface(if_a); _check_iface(if_b)
    planned = [
        ["ip", "link", "set", if_a, "down"],
        ["ip", "link", "set", if_b, "down"],
    ]
    journal.record(["ip", "link", "set", if_a, "up"])
    journal.record(["ip", "link", "set", if_b, "up"])
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
    _check_iface(iface)
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
