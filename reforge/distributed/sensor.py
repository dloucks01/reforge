"""Sensor — observe traffic at one point and report to a collector.

`sink` is a callable(Message) — in-process (collector.ingest) or a NetworkSink.
observe(pkt) extracts credentials and host/OS/service facts and emits them.
"""

from __future__ import annotations

from collections.abc import Callable

from reforge.attacks.creds import CredentialExtractor
from reforge.distributed.protocol import Message
from reforge.recon.assets import AssetInventory


class Sensor:
    def __init__(self, sensor_id: str, sink: Callable[[Message], None]):
        self.id = sensor_id
        self.sink = sink
        self.creds = CredentialExtractor()
        self.local = AssetInventory()
        self._sent_creds: set = set()

    def observe(self, pkt) -> None:
        # credentials
        try:
            for c in self.creds.extract(pkt):
                sig = (c.kind, c.username, c.secret, c.src, c.dst)
                if sig not in self._sent_creds:
                    self._sent_creds.add(sig)
                    self.sink(Message(self.id, "cred", c.as_dict()))
        except Exception:
            pass
        # host/os/service snapshots for both endpoints of the packet
        try:
            self.local.observe(pkt)
            for ip in self._endpoints(pkt):
                h = self.local.hosts.get(ip)
                if h is not None:
                    self.sink(Message(self.id, "host", {
                        "ip": h.ip, "mac": h.mac, "os_family": h.os_family,
                        "os_confidence": h.os_confidence, "services": dict(h.services),
                        "hostnames": sorted(h.hostnames)}))
        except Exception:
            pass

    def event(self, text: str) -> None:
        self.sink(Message(self.id, "event", {"text": text}))

    @staticmethod
    def _endpoints(pkt):
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        return [str(ip.src), str(ip.dst)] if ip else []
