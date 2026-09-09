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

# ethtool -K short name -> the long feature name `ethtool -k` prints, so we can
# read the CURRENT state of each offload for an exact revert.
_OFFLOAD_LONGNAME = {
    "tso": "tcp-segmentation-offload",
    "gso": "generic-segmentation-offload",
    "gro": "generic-receive-offload",
    "lro": "large-receive-offload",
    "rx": "rx-checksumming",
    "tx": "tx-checksumming",
    "sg": "scatter-gather",
    "rxvlan": "rx-vlan-offload",
    "txvlan": "tx-vlan-offload",
}


class HostState:
    """Reads an interface's current state so revert can restore it exactly.

    Every method returns None when the state can't be determined, in which case
    the caller falls back to the historical fixed-value assumption. Injectable so
    the revert logic is unit-testable without root."""

    def offload_on(self, iface: str, feat: str) -> bool | None:
        raise NotImplementedError

    def has_flag(self, iface: str, flag: str) -> bool | None:   # flag: promisc|allmulti
        raise NotImplementedError

    def ipv6_disabled(self, iface: str) -> bool | None:
        raise NotImplementedError


class LiveHostState(HostState):
    """Best-effort live reader via ethtool / ip / sysctl."""

    def offload_on(self, iface: str, feat: str) -> bool | None:
        long = _OFFLOAD_LONGNAME.get(feat, feat)
        out = _run(["ethtool", "-k", iface]).stdout
        for line in out.splitlines():
            name, _, val = line.partition(":")
            if name.strip() == long:
                return val.strip().startswith("on")
        return None

    def has_flag(self, iface: str, flag: str) -> bool | None:
        out = _run(["ip", "-d", "link", "show", iface]).stdout
        if not out:
            return None
        token = {"promisc": "PROMISC", "allmulti": "ALLMULTI"}[flag]
        return token in out

    def ipv6_disabled(self, iface: str) -> bool | None:
        out = _run(["sysctl", "-n", f"net.ipv6.conf.{iface}.disable_ipv6"]).stdout.strip()
        if out in ("0", "1"):
            return out == "1"
        return None


def _restore_state(apply: bool, state: HostState | None) -> HostState | None:
    """Use the caller's reader, or a live one when actually applying changes."""
    if state is not None:
        return state
    return LiveHostState() if apply else None


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


def prepare_capture_iface(iface: str, journal: RevertJournal, apply: bool = False,
                          state: HostState | None = None) -> list[list[str]]:
    """Return (and optionally execute) the commands to make `iface` capture-ready.

    - disable offloads
    - up + promisc + allmulti
    - flush IPv4/IPv6 addresses, disable IPv6 autoconf

    The revert journal records the interface's ACTUAL prior state (read via
    `state`, or a live reader when `apply=True`), so restoring an interface that
    already had, say, promisc on or an offload off leaves it as it was found —
    not forced back to a hardcoded default. When the prior state is unknown
    (plan-only, no reader), it falls back to the historical assumption.
    """
    _check_iface(iface)
    st = _restore_state(apply, state)
    planned: list[list[str]] = []

    for feat in OFFLOADS:
        planned.append(["ethtool", "-K", iface, feat, "off"])
        prior = st.offload_on(iface, feat) if st else None
        restore = "off" if prior is False else "on"     # unknown -> assume was on
        journal.record(["ethtool", "-K", iface, feat, restore])

    prior_promisc = st.has_flag(iface, "promisc") if st else None
    prior_allmulti = st.has_flag(iface, "allmulti") if st else None
    prior_ipv6_disabled = st.ipv6_disabled(iface) if st else None

    planned += [
        ["ip", "link", "set", iface, "up"],
        ["ip", "link", "set", iface, "promisc", "on"],
        ["ip", "link", "set", iface, "allmulticast", "on"],
        ["ip", "addr", "flush", "dev", iface],
        ["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6=1"],
    ]
    journal.record(["ip", "link", "set", iface, "promisc",
                    "on" if prior_promisc else "off"])
    journal.record(["ip", "link", "set", iface, "allmulticast",
                    "on" if prior_allmulti else "off"])
    journal.record(["sysctl", "-w", f"net.ipv6.conf.{iface}.disable_ipv6="
                    + ("1" if prior_ipv6_disabled else "0")])

    if apply:
        for cmd in planned:
            _run(cmd)
    else:
        for cmd in planned:
            log.info("[plan] %s", " ".join(cmd))
    return planned


def prepare_bridge(if_a: str, if_b: str, journal: RevertJournal,
                   apply: bool = False, state: HostState | None = None) -> list[list[str]]:
    """Prepare BOTH interfaces for a userspace transparent bridge.

    Each interface: offloads off, promisc + allmulti, no IP; plus host-stack
    suppression so the kernel doesn't answer traffic crossing the bridge. The
    journal captures every undo for a clean revert.
    """
    _check_iface(if_a); _check_iface(if_b)
    planned: list[list[str]] = []
    for iface in (if_a, if_b):
        planned += prepare_capture_iface(iface, journal, apply=apply, state=state)
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
    # The inet family carries only IPv4/IPv6, so a host-originated RST drop lives
    # here — but ARP is NOT seen by an inet hook. Host ARP must be dropped in a
    # dedicated `arp`-family table, or the suppression silently never matches.
    # Flush each chain first so repeated calls don't stack duplicate rules.
    planned = [
        ["nft", "add", "table", "inet", "reforge"],
        ["nft", "add", "chain", "inet", "reforge", "out",
         "{ type filter hook output priority 0 ; }"],
        ["nft", "flush", "chain", "inet", "reforge", "out"],
        ["nft", "add", "rule", "inet", "reforge", "out",
         "oifname", iface, "tcp", "flags", "rst", "drop"],
        ["nft", "add", "table", "arp", "reforge"],
        ["nft", "add", "chain", "arp", "reforge", "out",
         "{ type filter hook output priority 0 ; }"],
        ["nft", "flush", "chain", "arp", "reforge", "out"],
        ["nft", "add", "rule", "arp", "reforge", "out",
         "meta", "oifname", iface, "drop"],
    ]
    journal.record(["nft", "delete", "table", "inet", "reforge"])
    journal.record(["nft", "delete", "table", "arp", "reforge"])
    if apply:
        for cmd in planned:
            _run(cmd)
    else:
        for cmd in planned:
            log.info("[plan] %s", " ".join(cmd))
    return planned
