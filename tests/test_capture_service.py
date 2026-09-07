"""CaptureService threading test using the offline pcap backend."""

from __future__ import annotations

import time

from scapy.layers.inet import IP
from scapy.layers.l2 import Ether

from reforge.capture.base import Frame
from reforge.capture.pcap import PcapFileBackend, export_pcap
from reforge.core.capture_service import CaptureService


def test_service_captures_all(tmp_path):
    frames = [Frame(data=bytes(Ether() / IP(dst=f"10.0.0.{i}"))) for i in range(20)]
    path = tmp_path / "cap.pcap"
    export_pcap(path, frames)

    service = CaptureService(PcapFileBackend(path))
    service.start()

    # Wait for the pcap to drain (backend exhausts and the loop stops).
    deadline = time.time() + 5
    while service.running and time.time() < deadline:
        time.sleep(0.02)

    collected = service.drain()
    service.stop()

    assert len(collected) == 20
    assert service.captured == 20
    assert service.dropped == 0


def test_service_records_error_reason():
    import time

    from reforge.capture.base import BackendCaps
    from reforge.core.capture_service import CaptureService

    class DyingBackend:
        caps = BackendCaps(name="dying", l2_rewrite=False, inject=False,
                           max_speed_hint="n/a", needs_root=False, notes="")

        def open(self):
            pass

        def recv_burst(self, *a, **k):
            raise OSError(19, "No such device")

        def send_burst(self, frames):
            return 0

        def close(self):
            pass

    svc = CaptureService(DyingBackend())
    svc.start()
    for _ in range(50):
        if not svc.running:
            break
        time.sleep(0.01)
    assert not svc.running
    assert svc.error and "No such device" in svc.error
