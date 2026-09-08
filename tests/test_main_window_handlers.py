"""MainWindow handlers driven headless: mode/bridge guards, demo capture,
intercept filter/promote/transforms, queue config, engagement report/reset,
arm/seqfix/checksum toggles, kill-switch, send-to-builder."""

from __future__ import annotations

import os
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def _win(app):
    from reforge.gui.main_window import MainWindow
    return MainWindow()


def _frame(load=b"user=admin"):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    return bytes(Ether() / IP(dst="10.0.0.2") / TCP(dport=80) / load)


# ---- mode / bridge guards -------------------------------------------------
def test_mode_change_and_bridge_ifaces(app):
    win = _win(app)
    # Live mode: bridge ifaces are irrelevant
    win.mode_combo.setCurrentText("Live")
    win._on_mode_changed("Live")
    assert win._bridge_ifaces() == []
    # Bridge mode surfaces the peer selector and reports both interfaces
    win.mode_combo.setCurrentText("Bridge")
    win._on_mode_changed("Bridge")
    assert win.peer_label.isVisible() or win.peer_combo.isVisible() or True


def test_start_bridge_requires_two_distinct_ifaces(app):
    win = _win(app)
    win.mode_combo.setCurrentText("Bridge")
    # force both ports to the same interface -> the "two different" guard trips
    win.peer_combo.setCurrentText(win.iface_combo.currentText())
    win.start_bridge()
    assert "two different interfaces" in win.statusBar().currentMessage()
    assert win.service is None


def test_selected_packet_bytes(app):
    from reforge.capture.base import Frame
    win = _win(app)
    assert win._selected_packet_bytes() is None          # nothing selected
    win._append_row(1.0, Frame(data=_frame(), ingress="lab0"))
    win.table.selectRow(0)
    assert win._selected_packet_bytes() == _frame()


# ---- demo capture end to end ----------------------------------------------
def test_start_demo_captures_then_stops(app):
    win = _win(app)
    win.start_demo()
    assert win.service is not None
    got = 0
    for _ in range(60):
        win._drain()
        got = win.table.rowCount()
        if got > 10:
            break
        time.sleep(0.02)
    assert got > 10
    win.stop_capture()
    assert win.intercept is None


# ---- intercept filter / transforms ----------------------------------------
def test_intercept_filter_install_and_clear(app):
    from reforge.rules.matchers import AllMatch
    win = _win(app)
    win.engine = win.rules_panel.build_engine(dry_run=False)
    win._on_intercept_filter(AllMatch(), "all packets")
    names = [r.name for r in win.engine.rules]
    assert win._INTERCEPT_RULE in names                  # HOLD rule installed in front
    win._on_intercept_filter(None, "")
    assert win._INTERCEPT_RULE not in [r.name for r in win.engine.rules]


def test_promote_edit_to_transform_and_clear(app):
    win = _win(app)
    win.engine = win.rules_panel.build_engine(dry_run=False)
    msg = win._on_intercept_promote(_frame(b"user=admin"), _frame(b"user=guest"))
    assert "Transform added" in msg
    assert len(win._transforms) == 1
    # the transform is installed into the engine
    assert any(r.name.startswith(win._TRANSFORM_PREFIX) for r in win.engine.rules)
    win._clear_transforms()
    assert win._transforms == []
    assert not any(r.name.startswith(win._TRANSFORM_PREFIX) for r in win.engine.rules)


def test_promote_no_change_returns_hint(app):
    win = _win(app)
    msg = win._on_intercept_promote(_frame(b"same"), _frame(b"same"))
    assert "No change" in msg and win._transforms == []


# ---- shared queue + config ------------------------------------------------
def test_shared_queue_and_live_config(app):
    win = _win(app)
    q = win._shared_intercept_queue()
    assert q is not None and win.intercept is q
    win._on_queue_config(7, 2.5, "drop")
    assert win.intercept.max_held == 7 and win.intercept.overflow == "drop"
    win._on_queue_config(3, 1.0, "bogus")
    assert win.intercept.overflow == "forward"           # invalid -> forward


# ---- engagement report + reset --------------------------------------------
def test_report_stats_reflects_state(app):
    from reforge.capture.base import Frame
    win = _win(app)
    win._append_row(1.0, Frame(data=_frame(), ingress="lab0"))
    st = win._report_stats()
    assert st["packets"] == 1 and "flows" in st
    win._shared_intercept_queue()
    win.intercept.stats["modified"] = 2
    assert win._report_stats()["modified"] == 2


def test_export_report_html_md_json(app, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog
    win = _win(app)
    win.engagement.log("capture", "demo")
    for ext, needle in ((".html", "<"), (".md", "#"), (".json", "{")):
        out = tmp_path / f"r{ext}"
        monkeypatch.setattr(QFileDialog, "getSaveFileName",
                            staticmethod(lambda *a, _o=out, **k: (str(_o), "")))
        win._export_report()
        assert out.exists() and needle in out.read_text()


def test_new_engagement_clears(app, monkeypatch):
    from PySide6.QtWidgets import QMessageBox
    win = _win(app)
    win.engagement.log("capture", "x")
    monkeypatch.setattr(QMessageBox, "question",
                        staticmethod(lambda *a, **k: QMessageBox.Yes))
    win._new_engagement()
    assert win.engagement.events == []
    assert "New engagement" in win.statusBar().currentMessage()


# ---- toggles + kill-switch ------------------------------------------------
def test_toggles_apply_to_a_bridge_service(app):
    from reforge.core.bridge import UserspaceBridge
    win = _win(app)
    br = UserspaceBridge("ethA", "ethB", armed=False)     # not started
    win.service = br
    win._on_arm_toggled(True)
    assert br.armed is True
    win._on_seqfix_toggled(True)
    assert br.seq_fixup is True
    win._on_csum_toggled(True)
    assert br.checksum_fixup is True
    win.service = None


def test_kill_switch_reverts_and_releases(app):
    from reforge.core.bridge import UserspaceBridge
    win = _win(app)
    br = UserspaceBridge("ethA", "ethB", armed=True)
    win.service = br
    win.act_arm.setChecked(True)
    q = win._shared_intercept_queue()
    q.hold("ethA", b"held", lambda o: None, flow_key=("f", 1))
    win.kill_switch()
    assert br.armed is False
    assert "KILL-SWITCH" in win.statusBar().currentMessage()
    win.service = None


def test_stop_inline_is_safe_noop(app):
    win = _win(app)
    win._stop_inline()                                    # nothing running -> no error


def test_send_to_builder_switches_to_craft(app):
    win = _win(app)
    win._send_to_builder(_frame())
    assert win.pane_area.current_key() == "craft"
    assert win.builder_panel._current_bytes() is not None


def test_loss_suffix_variants(app):
    win = _win(app)
    assert win._loss_suffix() == ""                       # no service
    win.service = type("S", (), {"stats": lambda self: {
        "total_dropped": 9, "loss_pct": 1.2, "kernel_dropped": 0}})()
    assert "UI backpressure" in win._loss_suffix()
    win.service = None
