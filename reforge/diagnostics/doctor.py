"""Doctor — self-test / diagnostics checks (PLAN.md section 9).

Each check returns pass/fail + a human message + an optional one-click fix hint.
Phase 0 ships environment and dependency checks that run without root; interface
and pipeline checks are added as those subsystems land.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from typing import Callable

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
        return Check("pyside6", True, f"PySide6 {PySide6.__version__}")
    except Exception as exc:
        return Check("pyside6", False, str(exc), "apt install python3-pyside6")


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


CHECKS: list[Callable[[], Check]] = [
    _check_python,
    _check_scapy,
    _check_pyside,
    _check_netfilterqueue,
    _check_tools,
    _check_backends,
    _check_root,
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
