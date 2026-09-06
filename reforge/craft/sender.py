"""Transmit crafted/edited packets.

Thin wrapper over Scapy send. L2 send (sendp) puts raw Ethernet frames on the
wire; L3 send (send) lets the kernel route. send_receive does one request and
returns the first reply. Needs CAP_NET_RAW (root or the privileged helper).
"""

from __future__ import annotations

import time


def inject(iface: str, data: bytes, count: int = 1, interval: float = 0.0,
           l2: bool = True) -> int:
    """Send `data` `count` times on `iface`, `interval` seconds apart."""
    from scapy.all import conf  # noqa: F401 (init arch/sockets)
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import send, sendp

    sent = 0
    for i in range(max(1, count)):
        if l2:
            sendp(Ether(data), iface=iface, verbose=False)
        else:
            send(IP(data), iface=iface, verbose=False)
        sent += 1
        if interval and i < count - 1:
            time.sleep(interval)
    return sent


def send_receive(iface: str, data: bytes, timeout: float = 2.0, l2: bool = True):
    """Send one packet and return the first reply's bytes, or None."""
    from scapy.all import conf  # noqa: F401
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import sr1, srp1

    if l2:
        reply = srp1(Ether(data), iface=iface, timeout=timeout, verbose=False)
    else:
        reply = sr1(IP(data), iface=iface, timeout=timeout, verbose=False)
    return bytes(reply) if reply is not None else None
