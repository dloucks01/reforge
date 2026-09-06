"""Diagnostic bundle — one file the operator exports for offline analysis.

Collects doctor results, versions, interface state, live counters, the rule set,
and a tail of the log into a single JSON file. Best-effort: shell commands that
fail are recorded as errors rather than aborting the collection.
"""

from __future__ import annotations

import json
import platform
import shutil
import subprocess
import time
from pathlib import Path

from reforge.constants import LOG_DIR, VERSION
from reforge.diagnostics.doctor import run_checks


def _cmd(args: list[str]) -> str:
    if not shutil.which(args[0]):
        return f"<{args[0]} not found>"
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as exc:  # pragma: no cover
        return f"<error: {exc}>"


def _log_tail(lines: int = 200) -> str:
    logfile = LOG_DIR / "reforge.log"
    try:
        content = logfile.read_text(errors="replace").splitlines()
        return "\n".join(content[-lines:])
    except Exception:
        return ""


def collect(interfaces: list[str] | None = None, counters: dict | None = None,
            rules: list | None = None) -> dict:
    interfaces = interfaces or []
    iface_state = {}
    for iface in interfaces:
        iface_state[iface] = {
            "link": _cmd(["ip", "-d", "link", "show", iface]),
            "offloads": _cmd(["ethtool", "-k", iface]),
        }
    return {
        "tool": "reforge",
        "version": VERSION,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "doctor": [c.__dict__ for c in run_checks()],
        "interfaces": iface_state,
        "nftables": _cmd(["nft", "list", "ruleset"]),
        "counters": counters or {},
        "rules": rules or [],
        "log_tail": _log_tail(),
    }


def write_bundle(path: str | Path, **kwargs) -> Path:
    data = collect(**kwargs)
    target = Path(path)
    target.write_text(json.dumps(data, indent=2, default=str))
    return target
