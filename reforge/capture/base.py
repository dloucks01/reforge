"""Capture/forward backend interface.

Every backend (AF_PACKET, AF_XDP, PF_RING, DPDK, NFQUEUE) implements this same
narrow interface, so the pipeline, rules, dissection and GUI never change when a
faster backend is swapped in. Burst-oriented by design for high link speeds.
"""

from __future__ import annotations

import abc
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass
class Frame:
    """A raw frame moving through the pipeline.

    `data` is the on-wire bytes. `ingress` is the interface it arrived on; the
    forward loop decides egress. `meta` carries backend hints (timestamp,
    queue id, verdict handle for NFQUEUE, etc.).
    """

    data: bytes
    ingress: str = ""
    egress: str = ""
    meta: dict = field(default_factory=dict)


@dataclass
class BackendCaps:
    """What a backend supports, so the selector / Doctor can reason about it."""

    name: str
    l2_rewrite: bool = False        # can rewrite Ethernet/MAC/VLAN
    inject: bool = True             # can transmit crafted frames
    max_speed_hint: str = "1G"      # rough ceiling: 1G / 10G / 40G / 100G
    needs_root: bool = True
    # False means the host may *support* the tech (is_available can be True) but
    # this build has no working data plane, so open() will raise. recommend_backend
    # must not pick such a backend even when detected.
    has_dataplane: bool = True
    notes: str = ""


class CaptureBackend(abc.ABC):
    """Abstract capture + forward + inject backend."""

    caps: BackendCaps

    @classmethod
    @abc.abstractmethod
    def is_available(cls) -> tuple[bool, str]:
        """Return (available, human-readable reason)."""

    @abc.abstractmethod
    def open(self) -> None:
        """Acquire interfaces/queues. Idempotent."""

    @abc.abstractmethod
    def recv_burst(self, max_frames: int = 64, timeout: float = 0.5) -> list[Frame]:
        """Return up to `max_frames` captured frames (may be empty)."""

    @abc.abstractmethod
    def send_burst(self, frames: Iterable[Frame]) -> int:
        """Transmit frames on their egress interface. Return count sent."""

    @abc.abstractmethod
    def close(self) -> None:
        """Release resources. Idempotent; safe to call after a crash."""

    def __enter__(self) -> CaptureBackend:
        self.open()
        return self

    def __exit__(self, *exc) -> None:
        self.close()
