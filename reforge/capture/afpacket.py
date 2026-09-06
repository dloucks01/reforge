"""AF_PACKET / libpcap capture backend (compatibility floor).

Phase 0 stub: declares availability and capabilities and sketches the calls.
Phase 1 implements real capture via Scapy's L2 socket (or a raw AF_PACKET
socket with TPACKETv3 for throughput).
"""

from __future__ import annotations

from typing import Iterable

from reforge.capture.base import BackendCaps, CaptureBackend, Frame


class AfPacketBackend(CaptureBackend):
    caps = BackendCaps(
        name="af_packet",
        l2_rewrite=True,
        inject=True,
        max_speed_hint="1-2G",
        needs_root=True,
        notes="Universal fallback; works on any NIC/driver.",
    )

    def __init__(self, ifaces: list[str]):
        self.ifaces = ifaces
        self._sockets: dict[str, object] = {}

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        try:
            import scapy  # noqa: F401
        except Exception as exc:  # pragma: no cover
            return False, f"scapy import failed: {exc}"
        return True, "scapy present; AF_PACKET usable with CAP_NET_RAW"

    def open(self) -> None:
        # Phase 1: open one L2 socket per interface, set promisc + allmulti.
        raise NotImplementedError("AF_PACKET capture lands in Phase 1")

    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        raise NotImplementedError("AF_PACKET capture lands in Phase 1")

    def send_burst(self, frames: Iterable[Frame]) -> int:
        raise NotImplementedError("AF_PACKET inject lands in Phase 1")

    def close(self) -> None:
        for sock in self._sockets.values():
            try:
                sock.close()  # type: ignore[attr-defined]
            except Exception:
                pass
        self._sockets.clear()
