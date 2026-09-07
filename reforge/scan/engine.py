"""Scan orchestration — run a scanner over targets, grab banners, feed inventory.

Results flow into the same AssetInventory the passive recon builds, so active +
passive discovery share one network map.
"""

from __future__ import annotations

import socket

from reforge.recon.assets import AssetInventory
from reforge.scan.tcp import OPEN


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:  # pragma: no cover (net)
    """Connect to an open port and read a service banner (best-effort)."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
    except Exception:
        return ""
    try:
        s.settimeout(timeout)
        if port in (80, 8080, 8000):
            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode())
        data = s.recv(256)
        return data.decode("latin-1", "replace").splitlines()[0].strip() if data else ""
    except Exception:
        return ""
    finally:
        s.close()


class ScanEngine:
    def __init__(self, inventory: AssetInventory | None = None):
        self.inv = inventory or AssetInventory()

    def scan_ports(self, targets: list[str], ports: list[int], scanner,
                   banners: bool = True, banner_fn=grab_banner) -> dict[str, dict[int, str]]:
        results: dict[str, dict[int, str]] = {}
        for host in targets:
            states = scanner.scan(host, ports)
            results[host] = states
            h = self.inv._host(host)
            for port, state in states.items():
                if state == OPEN:
                    banner = banner_fn(host, port) if banners else ""
                    h.services[port] = ("open " + banner).strip()
        return results

    def open_ports(self, results: dict[str, dict[int, str]]) -> dict[str, list[int]]:
        return {host: [p for p, st in states.items() if st == OPEN]
                for host, states in results.items()}
