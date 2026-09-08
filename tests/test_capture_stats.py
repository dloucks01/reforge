"""CaptureService surfaces backend kernel drop stats when available."""

from __future__ import annotations

from reforge.capture.base import BackendCaps, CaptureBackend, Frame
from reforge.core.capture_service import CaptureService


class _StatBackend(CaptureBackend):
    caps = BackendCaps(name="fake")

    def __init__(self):
        self._sent = False
        self.received = 0
        self.drops = 0

    @classmethod
    def is_available(cls):
        return True, "fake"

    def open(self):
        pass

    def recv_burst(self, max_frames=64, timeout=0.5):
        if self._sent:
            return []
        self._sent = True
        return [Frame(data=b"\x00" * 20, ingress="fake", meta={"ts": 1.0})]

    def send_burst(self, frames):
        return 0

    def close(self):
        pass

    def capture_stats(self):
        return {"received": self.received, "dropped": self.drops}


def test_stats_dict_combines_queue_and_kernel():
    b = _StatBackend()
    svc = CaptureService(b)
    svc.captured = 100
    svc.dropped = 5                   # userspace queue drops
    svc.kern_dropped = 15             # kernel drops
    svc.kern_received = 120
    st = svc.stats()
    assert st["captured"] == 100
    assert st["queue_dropped"] == 5
    assert st["kernel_dropped"] == 15
    assert st["total_dropped"] == 20
    # loss = 20 / (100 + 20) = 16.67%
    assert st["loss_pct"] == 16.67


def test_poll_kernel_stats_reads_backend():
    b = _StatBackend()
    b.received, b.drops = 900, 3
    svc = CaptureService(b)
    svc._poll_kernel_stats()
    assert svc.kern_received == 900
    assert svc.kern_dropped == 3


def test_poll_kernel_stats_ignores_backend_without_stats():
    # a backend with no capture_stats() must not raise
    svc = CaptureService.__new__(CaptureService)
    svc.backend = object()
    svc.kern_received = 0
    svc.kern_dropped = 0
    svc._poll_kernel_stats()          # no attribute -> no-op
    assert svc.kern_dropped == 0
