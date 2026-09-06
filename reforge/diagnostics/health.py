"""Live health metrics for the dashboard.

Turns the raw counters exposed by a running capture/bridge service into rates
(pps/bps deltas) and pulls a few cheap system stats. No external deps.
"""

from __future__ import annotations

import os
import time


class RateMeter:
    """Computes per-second rates from successive counter snapshots."""

    def __init__(self):
        self._last: dict | None = None
        self._last_t: float | None = None

    def update(self, counters: dict, now: float | None = None) -> dict:
        now = time.monotonic() if now is None else now
        rates: dict[str, float] = {}
        if self._last is not None and self._last_t is not None:
            dt = now - self._last_t
            if dt > 0:
                for k, v in counters.items():
                    if isinstance(v, (int, float)):
                        rates[k + "_per_s"] = (v - self._last.get(k, 0)) / dt
        self._last = dict(counters)
        self._last_t = now
        return rates


def system_stats() -> dict:
    stats: dict[str, object] = {"cpu_count": os.cpu_count()}
    try:
        stats["loadavg"] = tuple(round(x, 2) for x in os.getloadavg())
    except (OSError, AttributeError):
        stats["loadavg"] = None
    return stats


def snapshot(service, meter: RateMeter | None = None) -> dict:
    """Build a health snapshot from a running service (bridge or capture)."""
    counters = {}
    if service is not None and hasattr(service, "counters"):
        c = service.counters
        counters = c.as_dict() if hasattr(c, "as_dict") else dict(c)
    elif service is not None:
        counters = {"captured": getattr(service, "captured", 0),
                    "dropped": getattr(service, "dropped", 0)}

    snap = {
        "running": bool(getattr(service, "running", False)),
        "counters": counters,
        "system": system_stats(),
    }
    if meter is not None:
        snap["rates"] = meter.update(counters)
    return snap
