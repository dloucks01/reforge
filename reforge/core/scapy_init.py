"""One-time Scapy layer warmup.

Scapy imports protocol layers lazily, and the *first* import of some layers
(notably scapy.layers.inet6) rebinds dissectors as a side effect — which can
corrupt the dissection of packets processed in the same moment. Importing the
layers we rely on once, up front, makes dissection deterministic. Call warmup()
at process entry points and before any packet parsing.
"""

from __future__ import annotations

import logging

log = logging.getLogger("reforge.scapy_init")

_DONE = False


def warmup() -> None:
    global _DONE
    if _DONE:
        return
    try:
        import scapy.layers.dhcp
        import scapy.layers.dns
        import scapy.layers.inet
        import scapy.layers.inet6
        import scapy.layers.l2
        import scapy.layers.snmp  # noqa: F401
    except Exception:
        # A partial/broken Scapy import is exactly the failure warmup exists to
        # prevent (non-deterministic dissection). Surface it rather than hiding it.
        log.warning("scapy layer warmup failed; dissection may be non-deterministic",
                    exc_info=True)
    _DONE = True
