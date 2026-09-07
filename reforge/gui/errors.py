"""Operator-facing error explanations.

Turns a raw exception into a short message plus a likely cause, so a status line
says 'needs root or CAP_NET_RAW' instead of a bare 'Operation not permitted'.
Used across the attack techniques and anywhere a caught error is shown.
"""

from __future__ import annotations

import errno


def _hint(exc, low: str) -> str:
    eno = getattr(exc, "errno", None)
    if (isinstance(exc, PermissionError) or eno == errno.EPERM
            or "operation not permitted" in low or "permission denied" in low):
        return "needs root or CAP_NET_RAW — start via the privileged helper"
    if eno == errno.ENODEV or "no such device" in low or "no such interface" in low:
        return "interface not found or down — check the name (ip link)"
    if eno == errno.EADDRNOTAVAIL or "cannot assign requested address" in low:
        return "that address is not available on this host"
    if eno == errno.EADDRINUSE or "address already in use" in low:
        return "the port is already in use"
    if eno == errno.EHOSTUNREACH or "no route to host" in low:
        return "no route to host — wrong segment or the host is down"
    if "getmacbyip" in low or "mac address" in low or "could not resolve" in low:
        return "target unreachable or not on this segment"
    if "name or service not known" in low or "temporary failure in name resolution" in low:
        return "cannot resolve that name (airgapped?) — use an IP"
    return ""


def explain(exc) -> str:
    """A concise 'message — likely cause' string for an exception or message.

    Accepts a caught exception or an already-formatted error string (e.g. a
    stored stop reason), appending a likely-cause hint when one is recognized."""
    if isinstance(exc, str):
        msg = exc.strip()
        hint = _hint(None, msg.lower())
    else:
        msg = str(exc).strip() or exc.__class__.__name__
        hint = _hint(exc, msg.lower())
    return f"{msg} — {hint}" if hint else msg
