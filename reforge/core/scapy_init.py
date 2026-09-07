"""One-time Scapy layer warmup.

Scapy imports protocol layers lazily, and the *first* import of some layers
(notably scapy.layers.inet6) rebinds dissectors as a side effect — which can
corrupt the dissection of packets processed in the same moment. Importing the
layers we rely on once, up front, makes dissection deterministic. Call warmup()
at process entry points and before any packet parsing.
"""

from __future__ import annotations

_DONE = False


def warmup() -> None:
    global _DONE
    if _DONE:
        return
    try:
        import scapy.layers.dhcp  # noqa: F401
        import scapy.layers.dns  # noqa: F401
        import scapy.layers.inet  # noqa: F401
        import scapy.layers.inet6  # noqa: F401
        import scapy.layers.l2  # noqa: F401
        import scapy.layers.snmp  # noqa: F401
    except Exception:
        pass
    _DONE = True
