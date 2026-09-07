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


def _panel_with(app, data: bytes, kind: str = "packet"):
    from reforge.core.intercept import InterceptQueue
    from reforge.gui.intercept_panel import InterceptPanel

    panel = InterceptPanel()
    q = InterceptQueue()
    panel.set_queue(q)
    out: dict = {}
    q.hold("ifa", data, lambda o: out.__setitem__("v", o), flow_key=("f", 1),
           kind=kind, meta={"summary": "x", "from_client": True})
    panel.refresh_pending()
    panel.table.selectRow(0)
    panel._on_select()
    return panel, out


def test_intercept_editor_hex_and_ascii_packet(app):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    pkt = bytes(Ether() / IP(dst="10.0.0.2") / TCP(dport=80) / Raw(b"user=admin"))
    panel, out = _panel_with(app, pkt)
    assert panel._view == "hex"                         # packets default to hex
    # ascii view edits text
    panel.view_combo.setCurrentText("ASCII")
    txt = panel.hex_edit.toPlainText()
    assert "user=admin" in txt
    panel.hex_edit.setPlainText(txt.replace("admin", "guest"))
    panel._resolve("modify")
    assert out["v"].endswith(b"user=guest")


def test_intercept_editor_hex_edit_packet(app):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    pkt = bytes(Ether() / IP(dst="10.0.0.2") / TCP(dport=80) / Raw(b"AB"))
    panel, out = _panel_with(app, pkt)
    toks = panel.hex_edit.toPlainText().split()
    toks[-1] = "58"                                     # 'B' -> 'X'
    panel.hex_edit.setPlainText(" ".join(toks))
    panel._resolve("modify")
    assert out["v"].endswith(b"AX")


def test_intercept_editor_message_ascii_crlf(app):
    req = b"POST /login HTTP/1.1\r\nHost: t\r\n\r\nuser=admin"
    panel, out = _panel_with(app, req, kind="message")
    assert panel._view == "ascii" and not panel.tree.isVisible()
    # toggling to hex and back is lossless
    panel.view_combo.setCurrentText("Hex")
    assert panel.hex_edit.toPlainText().split()[0] == "50"   # 'P'
    panel.view_combo.setCurrentText("ASCII")
    t = panel.hex_edit.toPlainText()
    panel.hex_edit.setPlainText(t.replace("admin", "guest"))
    panel._resolve("modify")
    assert out["v"] == req.replace(b"admin", b"guest")       # CRLF preserved


def test_intercept_editor_rejects_bad_hex(app):
    from scapy.layers.l2 import Ether

    panel, _ = _panel_with(app, bytes(Ether()))
    panel.hex_edit.setPlainText("zz not hex")
    assert panel._sync_from_editor() is False


def test_guide_tab_and_intros_present(app):
    from reforge.gui.guidance import SECTIONS, PanelIntro
    from reforge.gui.main_window import MainWindow

    win = MainWindow()
    titles = [win.tabs.tabText(i) for i in range(win.tabs.count())]
    assert "Guide" in titles
    # each non-Guide tab carries an intro strip
    for name in ("Capture", "Builder", "Attacks", "Scan"):
        w = win.tabs.widget(titles.index(name))
        assert w.findChild(PanelIntro) is not None, f"{name} missing intro"
    # the guide indexes every section plus the filter cheat sheet
    labels = [win.guide_panel.index.item(i).text() for i in range(win.guide_panel.index.count())]
    assert len(labels) == len(SECTIONS) + 1 and "Filter syntax" in labels


def test_open_guide_navigates_and_scrolls(app):
    from reforge.gui.main_window import MainWindow

    win = MainWindow()
    win._open_guide("intercept")
    assert win.tabs.tabText(win.tabs.currentIndex()) == "Guide"
    win.guide_panel.scroll_to("_filter")            # must not raise


def test_intercept_presets_fill_filter(app):
    from reforge.gui.main_window import MainWindow

    win = MainWindow()
    ip = win.intercept_panel
    captured = {}
    ip.on_filter = lambda m, t: captured.update(match=m, text=t)
    ip._apply_preset(1)                             # first real preset
    assert ip.enable_check.isChecked()
    assert ip.filter_edit.text() and captured.get("match") is not None
    assert ip.preset_combo.currentIndex() == 0      # resets like a menu


def test_builder_templates_build(app):
    from reforge.craft import builder
    from reforge.gui.builder_panel import _TEMPLATES, BuilderPanel

    for _name, spec in _TEMPLATES:                  # every template is valid
        assert len(builder.spec_to_bytes(spec)) >= 14
    bp = BuilderPanel()
    bp._apply_template(2)                           # HTTP GET
    assert [lyr["layer"] for lyr in bp.layers][:2] == ["Ether", "IP"]
    assert bp.template_combo.currentIndex() == 0
    assert bp._current_bytes() is not None


def test_scan_port_presets(app):
    from reforge.gui.scan_panel import _PORT_SETS, ScanPanel

    sp = ScanPanel()
    sp._apply_port_preset(2)
    assert sp.ports.text() == _PORT_SETS[1][1]
    assert sp.port_preset.currentIndex() == 0


def test_attacks_quick_setups(app):
    from reforge.gui.attacks_panel import _QUICK_SETUPS, AttacksPanel

    ap = AttacksPanel()
    ap._apply_quick_setup(2)                        # sslstrip
    assert ap.tp_sslstrip.isChecked() and ap.tp_stripenc.isChecked()
    assert not ap.tp_cookie.isChecked() and ap.tp_quick.currentIndex() == 0
    ap._apply_quick_setup(len(_QUICK_SETUPS))       # Hold logins for edit
    assert ap.tp_intercept.isChecked() and ap.tp_int_keyword.text() == "login"
    assert ap.tp_int_dir.currentText() == "requests"


def test_remembered_settings_roundtrip(app):
    from reforge.gui.main_window import MainWindow
    from reforge.gui.settings import settings

    settings().clear()
    w = MainWindow()
    w.scan_panel.ports.setText("1-1024")
    w.scan_panel.target.setText("10.0.0.0/24")
    w.intercept_panel.limit_spin.setValue(7)
    w.intercept_panel.filter_edit.setText("TCP.dport == 443")
    w.bpf_edit.setText("tcp port 80")
    w._save_settings()

    w2 = MainWindow()                               # fresh window restores them
    assert w2.scan_panel.ports.text() == "1-1024"
    assert w2.scan_panel.target.text() == "10.0.0.0/24"
    assert w2.intercept_panel.limit_spin.value() == 7
    assert w2.intercept_panel.filter_edit.text() == "TCP.dport == 443"
    assert w2.bpf_edit.text() == "tcp port 80"
    assert not w2.intercept_panel.enable_check.isChecked()   # never auto-arms intercept
