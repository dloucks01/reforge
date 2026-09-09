"""Doctor — self-test / diagnostics checks (PLAN.md section 9).

Each check returns pass/fail + a human message + an optional one-click fix hint.
Phase 0 ships environment and dependency checks that run without root; interface
and pipeline checks are added as those subsystems land.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass

from reforge.capture.registry import list_backends


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""      # human-readable remediation / one-click fix hint


def _check_python() -> Check:
    import sys

    ok = sys.version_info >= (3, 11)
    return Check("python", ok, f"Python {sys.version.split()[0]}",
                 "" if ok else "Reforge needs Python 3.11+")


def _check_scapy() -> Check:
    try:
        import scapy
        return Check("scapy", True, f"scapy {scapy.__version__}")
    except Exception as exc:
        return Check("scapy", False, str(exc), "pip/apt install python3-scapy")


def _check_pyside() -> Check:
    try:
        import PySide6

        # The base package can be present without the compiled Qt modules;
        # the GUI needs QtWidgets/QtCore/QtGui specifically.
        from PySide6 import QtCore, QtGui, QtWidgets  # noqa: F401
        return Check("pyside6", True, f"PySide6 {PySide6.__version__} (Qt {QtCore.qVersion()})")
    except Exception as exc:
        return Check("pyside6", False, str(exc),
                     "apt install python3-pyside6.qtwidgets python3-pyside6.qtcore "
                     "python3-pyside6.qtgui")


def _check_netfilterqueue() -> Check:
    try:
        import netfilterqueue  # noqa: F401
        return Check("netfilterqueue", True, "present (NFQUEUE mode available)")
    except Exception as exc:
        return Check("netfilterqueue", False, str(exc),
                     "apt install python3-netfilterqueue")


def _check_tools() -> Check:
    needed = ["ip", "ethtool", "nft"]
    missing = [t for t in needed if not shutil.which(t)]
    ok = not missing
    return Check("cli-tools", ok,
                 "found: " + ", ".join(t for t in needed if shutil.which(t)),
                 "" if ok else f"install: {', '.join(missing)}")


def _check_root() -> Check:
    is_root = os.geteuid() == 0
    return Check("privileges", True,
                 "running as root" if is_root else "unprivileged (use the helper)",
                 "" if is_root else "start: sudo python -m reforge.privhelper.helper")


def _check_backends() -> Check:
    rows = list_backends()
    avail = [n for n, ok, _ in rows if ok]
    return Check("backends", bool(avail),
                 "available: " + (", ".join(avail) or "none"),
                 "" if avail else "no capture backend usable")


# ---------------------------------------------------------------------------
# Inline preflight: the host-level blockers that fail *silently* mid-attack —
# a poisoned victim's traffic reaches the attacker but never gets relayed or
# manipulated because the kernel drops it. Catch them before arming so "no
# traffic" becomes an explained, fixable blocker instead of a dead attack.
# ---------------------------------------------------------------------------
def _read(path: str) -> str:
    with open(path) as f:
        return f.read()


def _run_text(*args: str) -> str:
    import subprocess
    try:
        return subprocess.run(list(args), capture_output=True, text=True,
                              timeout=5, check=False).stdout
    except Exception:
        return ""


def parse_forward_policy(iptables_forward_output: str) -> str | None:
    """Extract the FORWARD chain default policy from `iptables -L FORWARD`."""
    import re
    m = re.search(r"Chain FORWARD \(policy (\w+)\)", iptables_forward_output)
    return m.group(1) if m else None


def interpret_rp_filter(all_val: str, default_val: str) -> tuple[bool, str]:
    """(ok, note) for the effective reverse-path filter mode. Strict (1) can drop
    same-segment MITM relay; 0 (off) and 2 (loose) are fine."""
    vals = [all_val.strip(), default_val.strip()]
    if "1" in vals:
        return False, "strict — may drop same-segment MITM relay"
    return True, "loose/off"


def check_forward_policy() -> Check:
    pol = parse_forward_policy(_run_text("iptables", "-L", "FORWARD", "-n"))
    if pol is None:
        return Check("forward-policy", True, "unknown (needs root/iptables to read)")
    if pol == "DROP":
        return Check("forward-policy", False,
                     "FORWARD chain policy is DROP — relayed victim traffic is dropped "
                     "(common with Docker/firewalld)",
                     "iptables -I FORWARD -s <victim-subnet> -j ACCEPT  (or -P FORWARD ACCEPT)")
    return Check("forward-policy", True, f"FORWARD policy {pol}")


def check_rp_filter() -> Check:
    try:
        a = _read("/proc/sys/net/ipv4/conf/all/rp_filter")
        d = _read("/proc/sys/net/ipv4/conf/default/rp_filter")
    except Exception:
        return Check("rp-filter", True, "unknown")
    ok, note = interpret_rp_filter(a, d)
    fix = "sysctl -w net.ipv4.conf.all.rp_filter=2" if not ok else ""
    return Check("rp-filter", ok, f"rp_filter all/default = {a.strip()}/{d.strip()} ({note})", fix)


def check_ip_forwarding() -> Check:
    try:
        on = _read("/proc/sys/net/ipv4/ip_forward").strip() == "1"
    except Exception:
        return Check("ip-forward", True, "unknown")
    return Check("ip-forward", True,
                 "IPv4 forwarding on" if on
                 else "IPv4 forwarding off (a MITM enables it; needs root)")


def check_nfqueue_ready() -> Check:
    try:
        import netfilterqueue  # noqa: F401
        have_nfq = True
    except Exception:
        have_nfq = False
    have_nft = bool(shutil.which("nft"))
    if have_nfq and have_nft:
        return Check("nfqueue-ready", True, "netfilterqueue + nft present (NFQUEUE inline ready)")
    missing = ([] if have_nfq else ["python3-netfilterqueue"]) + ([] if have_nft else ["nftables"])
    return Check("nfqueue-ready", False, "NFQUEUE inline path unavailable",
                 "apt install " + ", ".join(missing))


_RISKY_OFFLOADS = ("tx-checksumming", "rx-checksumming",
                   "generic-segmentation-offload", "tcp-segmentation-offload")


def parse_offloads_on(ethtool_k_output: str) -> list[str]:
    """Offloads reported 'on' that corrupt re-injected bridge frames."""
    return [f for f in _RISKY_OFFLOADS if f"{f}: on" in ethtool_k_output]


def check_offloads(iface: str) -> Check:
    out = _run_text("ethtool", "-k", iface)
    if not out:
        return Check(f"offloads/{iface}", True, "unknown")
    risky = parse_offloads_on(out)
    if risky:
        return Check(f"offloads/{iface}", False,
                     f"{iface}: offloads on ({', '.join(risky)}) — re-injected bridge frames "
                     "carry bad checksums and get dropped",
                     f"ethtool -K {iface} tx off rx off gso off tso off")
    return Check(f"offloads/{iface}", True, f"{iface}: offloads off")


# host-level checks common to any inline path (NFQUEUE or bridge)
INLINE_CHECKS: list[Callable[[], Check]] = [
    check_nfqueue_ready, check_forward_policy, check_rp_filter, check_ip_forwarding,
]


def run_inline_preflight(ifaces: list[str] | None = None) -> list[Check]:
    """Readiness checks to run before arming inline manipulation. Pass the bridge
    interfaces to also flag NIC offloads that break frame re-injection."""
    checks = [c() for c in INLINE_CHECKS]
    for i in ifaces or []:
        checks.append(check_offloads(i))
    return checks


def inline_blockers(ifaces: list[str] | None = None) -> list[Check]:
    """Just the preflight checks that will actually block inline traffic."""
    return [c for c in run_inline_preflight(ifaces) if not c.ok]


@dataclass
class EngineAdvice:
    """A recommendation between the two inline engines, with the trade-off named."""
    engine: str | None          # "bridge" | "nfqueue" | None (neither ready)
    reason: str                 # why this engine fits the detected topology
    tradeoff: str               # what it costs / demands
    alternative: str            # the other engine and when to prefer it


_BRIDGE_TRADEOFF = ("both NICs are dedicated (no IP, promiscuous, offloads off) and "
                    "you must sit physically between the two cables")
_NFQUEUE_TRADEOFF = ("needs root, nft + netfilterqueue, IP forwarding and a FORWARD-accept "
                     "policy; you appear as an extra L3 hop and the poisoning is detectable")
_ALT_BRIDGE = ("Two NICs and can splice the link? A userspace Bridge is a transparent L2 "
               "tap — no poisoning, no routing footprint.")
_ALT_NFQUEUE = ("One NIC only? Pair NFQUEUE with an ARP/NDP MITM to get on-path by poisoning "
                "instead.")


def recommend_inline_engine(iface_count: int, nfqueue_ok: bool,
                            mitm_active: bool = False) -> EngineAdvice:
    """Guide the choice between the two inline engines from the host's topology.

    - Userspace bridge: a transparent L2 tap between two segments. Needs two
      dedicated NICs; no poisoning, no L3 footprint. Best for a wired inline splice.
    - NFQUEUE: relays a MITM'd/routed flow through the kernel FORWARD chain into the
      rule engine. One NIC; needs the nfqueue stack + forwarding. Best when you are
      already on-path via poisoning, or the host is the gateway.
    """
    can_bridge = iface_count >= 2
    if mitm_active and nfqueue_ok:
        return EngineAdvice("nfqueue",
            "a MITM is active — relay the poisoned flow through the kernel FORWARD chain",
            _NFQUEUE_TRADEOFF, _ALT_BRIDGE)
    if can_bridge:
        return EngineAdvice("bridge",
            "two interfaces available — a transparent L2 tap needs no poisoning and "
            "leaves no L3 footprint", _BRIDGE_TRADEOFF, _ALT_NFQUEUE)
    if nfqueue_ok:
        return EngineAdvice("nfqueue",
            "a single interface — pair NFQUEUE with an ARP/NDP MITM to get on-path",
            _NFQUEUE_TRADEOFF, _ALT_BRIDGE)
    return EngineAdvice(None,
        "no inline engine ready",
        "need a second interface for a Bridge, or netfilterqueue + nft for NFQUEUE",
        "Attach a second NIC, or install the nfqueue stack (apt install nftables "
        "python3-netfilterqueue).")


CHECKS: list[Callable[[], Check]] = [
    _check_python,
    _check_scapy,
    _check_pyside,
    _check_netfilterqueue,
    _check_tools,
    _check_backends,
    _check_root,
    *INLINE_CHECKS,
]


def run_checks() -> list[Check]:
    return [c() for c in CHECKS]


def run_doctor(as_json: bool = False) -> int:
    results = run_checks()
    if as_json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        for r in results:
            mark = "PASS" if r.ok else "FAIL"
            line = f"[{mark}] {r.name:16s} {r.detail}"
            if not r.ok and r.fix:
                line += f"\n       fix: {r.fix}"
            print(line)
    return 0 if all(r.ok for r in results) else 1
