"""Headless GUI construction smoke test (offscreen Qt platform).

Verifies the Phase 1 window builds and can ingest a frame into its table without
a display or live capture. Skipped if Qt can't start even offscreen.
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    try:
        from PySide6.QtWidgets import QApplication
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"PySide6 unavailable: {exc}")
    instance = QApplication.instance() or QApplication([])
    yield instance


def test_window_builds_and_appends(app):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from reforge.capture.base import Frame
    from reforge.gui.main_window import MainWindow

    win = MainWindow()
    frame = Frame(data=bytes(Ether() / IP(dst="10.0.0.9") / TCP(dport=443)))
    win._append_row(1.0, frame)

    assert win.table.rowCount() == 1
    assert win.table.item(0, 4).text() == "TCP"      # Proto column
    assert win.table.item(0, 3).text() == "10.0.0.9"  # Destination column

    # Selecting the row populates tree + hex.
    win.table.selectRow(0)
    win._on_select()
    assert win.tree.topLevelItemCount() >= 3          # Ether/IP/TCP
    assert win.hex.toPlainText().startswith("00000000")
    win.close()


def test_open_pcap_loads_and_autostops(app, tmp_path):
    """Regression: draining an exhausted pcap must auto-stop without recursion."""
    import time

    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.utils import wrpcap

    from reforge.capture.pcap import PcapFileBackend
    from reforge.core.capture_service import CaptureService
    from reforge.gui.main_window import MainWindow

    path = tmp_path / "e2e.pcap"
    wrpcap(str(path), [Ether() / IP(dst=f"10.0.0.{i}") / UDP(dport=53) for i in range(8)])

    win = MainWindow()
    win._start_service(CaptureService(PcapFileBackend(str(path))), "pcap e2e")
    for _ in range(50):  # pump the timer manually
        win._drain()
        if win.service is None:  # auto-stopped
            break
        time.sleep(0.01)

    assert win.service is None            # capture auto-stopped cleanly
    assert win.table.rowCount() == 8      # all frames loaded
    win.close()
