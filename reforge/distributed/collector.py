"""Central collector — merge observations from many sensors into one picture."""

from __future__ import annotations

import threading

from reforge.distributed.protocol import Message
from reforge.recon.assets import AssetInventory
from reforge.scenario.report import Report


class Collector:
    def __init__(self):
        self.inventory = AssetInventory()
        self.creds: list[dict] = []
        self.events: list[dict] = []
        self.sensors: set[str] = set()
        self._seen_creds: set = set()
        self._lock = threading.Lock()      # multiple sensor threads ingest concurrently

    def ingest(self, msg: Message) -> None:
        with self._lock:
            self.sensors.add(msg.sensor)
            if msg.kind == "host":
                self._merge_host(msg.data)
            elif msg.kind == "cred":
                self._merge_cred(msg.data)
            elif msg.kind == "event":
                self.events.append({"sensor": msg.sensor, **msg.data})
            elif msg.kind == "scan":
                self._merge_host({"ip": msg.data["ip"],
                                  "services": {int(p): "open" for p in msg.data.get("open", [])}})

    def ingest_line(self, line: bytes | str) -> None:
        self.ingest(Message.decode(line))

    def _merge_host(self, d: dict) -> None:
        h = self.inventory._host(d["ip"], d.get("mac", ""))
        if d.get("os_family") and not h.os_family:
            h.os_family = d["os_family"]
            h.os_confidence = d.get("os_confidence", "")
        for port, svc in (d.get("services") or {}).items():
            h.services[int(port)] = svc
        for name in d.get("hostnames") or []:
            h.hostnames.add(name)

    def _merge_cred(self, d: dict) -> None:
        sig = (d.get("kind"), d.get("username"), d.get("secret"), d.get("src"), d.get("dst"))
        if sig not in self._seen_creds:
            self._seen_creds.add(sig)
            self.creds.append(d)

    def report(self, name: str = "distributed-collection") -> Report:
        with self._lock:                          # consistent snapshot vs. concurrent ingest
            hosts = [{"ip": h.ip, "mac": h.mac, "os_family": h.os_family,
                      "services": dict(h.services), "hostnames": sorted(h.hostnames)}
                     for h in self.inventory.list_hosts()]
            creds = list(self.creds)
            events = list(self.events)
            sensors = sorted(self.sensors)
        return Report(name=name, hosts=hosts, credentials=creds, events=events,
                      notes=[f"sensors: {', '.join(sensors)}"])
