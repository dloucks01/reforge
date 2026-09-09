"""Test-case minimization — shrink a crashing/anomalous input to the essentials.

Delta-debugging (ddmin-style) over byte chunks: repeatedly try removing spans of
the input and keep the removal whenever the target still misbehaves. A minimal
repro is far easier to triage than the raw fuzz case, and it still carries the
finding's seed for reproducibility.

`ddmin` is pure (bytes + a predicate), so it is fully offline-testable with a
fake predicate; `still_anomalous` wires a live target + monitor into a predicate.
"""

from __future__ import annotations

from typing import Callable

from reforge.fuzzing import monitor as mon


def ddmin(data: bytes, predicate: Callable[[bytes], bool], min_chunk: int = 1) -> bytes:
    """Return the smallest subsequence of `data` for which `predicate` is True.

    Classic delta-debugging: start with 2 partitions, remove one span at a time,
    and increase granularity when a full pass removes nothing. `predicate` must be
    monotone-ish (True on `data` itself) or the input is returned unchanged.
    """
    if not data or not predicate(data):
        return data
    n = 2
    while len(data) >= 2:
        chunk = max(len(data) // n, min_chunk)
        i = 0
        removed = False
        while i < len(data):
            candidate = data[:i] + data[i + chunk:]
            if candidate and predicate(candidate):
                data = candidate
                n = max(n - 1, 2)
                removed = True
            else:
                i += chunk
        if not removed:
            if n >= len(data):
                break
            n = min(n * 2, len(data))
    return data


def still_anomalous(send_receive: Callable, prefix: list[bytes] | None = None,
                    baseline: int = 1) -> Callable[[bytes], bool]:
    """Build a ddmin predicate: replay optional stateful `prefix`, then the
    candidate, on a FRESH monitor each trial, and report whether the target's
    response is still a finding (not NORMAL / not a plain baseline reply).

    A fresh monitor per trial keeps minimization independent of campaign order.
    `baseline` primes the monitor with that many normal replies so a sustained
    loss of response can still register as a crash during minimization.
    """
    def predicate(candidate: bytes) -> bool:
        m = mon.TargetMonitor(crash_after=1)
        # prime a baseline so "stopped responding" can classify as CRASH
        for _ in range(baseline):
            m.classify(mon.Response(reply=b"\x00" * 4, latency=0.0))
        for p in (prefix or []):
            send_receive(p)
        cls = m.classify(send_receive(candidate))
        return mon.is_finding(cls) or cls == mon.NO_RESPONSE

    return predicate
