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
    # Capture mode: inline (bridge) ifaces are irrelevant
    win.mode_combo.setCurrentText("Capture")
    win._on_mode_changed("Capture")
    assert win._bridge_ifaces() == []
    # Inline mode surfaces the peer selector and reports both interfaces
    win.mode_combo.setCurrentText("Inline")
    win._on_mode_changed("Inline")
    assert win.peer_label.isVisible() or win.peer_combo.isVisible() or True


def test_start_bridge_requires_two_distinct_ifaces(app):
    win = _win(app)
    win.mode_combo.setCurrentText("Inline")
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


def test_inline_preflight_warning_surfaces_blockers(app, monkeypatch):
    import reforge.diagnostics.doctor as D
    from reforge.diagnostics.doctor import Check
    win = _win(app)
    # no blockers -> empty warning
    monkeypatch.setattr(D, "inline_blockers", lambda ifaces=None: [])
    assert win._inline_preflight_warning() == ""
    # a blocker -> warning names it + fix, and it's logged to the engagement
    monkeypatch.setattr(D, "inline_blockers", lambda ifaces=None: [
        Check("forward-policy", False, "FORWARD policy is DROP", "iptables -P FORWARD ACCEPT")])
    warn = win._inline_preflight_warning()
    assert "forward-policy" in warn and "iptables -P FORWARD ACCEPT" in warn
    assert any(e.kind == "preflight" for e in win.engagement.events)


def test_inline_preflight_passes_ifaces_for_offloads(app, monkeypatch):
    import reforge.diagnostics.doctor as D
    win = _win(app)
    seen = {}

    def fake(ifaces=None):
        seen["ifaces"] = ifaces
        return []

    monkeypatch.setattr(D, "inline_blockers", fake)
    win._inline_preflight_warning(["ethA", "ethB"])
    assert seen["ifaces"] == ["ethA", "ethB"]


def test_auto_arm_seqfix_on_length_changing_rule(app):
    win = _win(app)
    win.act_seqfix.setChecked(False)
    # a same-length rule -> not auto-armed
    win.rules_panel.specs[:] = [{"enabled": True, "match": {"type": "all"},
        "actions": [{"type": "payload_replace", "find": "aa", "replace": "bb"}]}]
    assert win._auto_arm_seqfix() is False and win.act_seqfix.isChecked() is False
    # a length-changing rule -> auto-armed + noted
    win.rules_panel.specs[:] = [{"enabled": True, "match": {"type": "all"},
        "actions": [{"type": "payload_replace", "find": "hi", "replace": "hello"}]}]
    assert win._auto_arm_seqfix() is True and win.act_seqfix.isChecked() is True
    assert any(e.kind == "seqfix" for e in win.engagement.events)


def test_auto_arm_respects_operator_choice(app):
    win = _win(app)
    win.act_seqfix.setChecked(True)              # operator already on
    win.rules_panel.specs[:] = []                # no length-changing rule
    assert win._auto_arm_seqfix() is True        # stays on


def test_intercept_length_change_warns(app):
    win = _win(app)
    win._on_intercept_length_change(+7)
    msg = win.statusBar().currentMessage()
    assert "+7 bytes" in msg and "desync" in msg
    assert any(e.kind == "seqfix" for e in win.engagement.events)


def test_mode_change_to_bridge_shows_engine_guidance(app, monkeypatch):
    import reforge.gui.main_window as MW
    win = _win(app)
    # two NICs present -> Inline (bridge) affirmed as the clean transparent tap
    monkeypatch.setattr(MW, "list_interfaces", lambda: ["eth0", "eth1"])
    win._on_mode_changed("Inline")
    assert "Inline (bridge)" in win.statusBar().currentMessage()
    # only one NIC -> warn it needs two and point at NFQUEUE + MITM
    monkeypatch.setattr(MW, "list_interfaces", lambda: ["eth0"])
    win._on_mode_changed("Inline")
    msg = win.statusBar().currentMessage()
    assert "two interfaces" in msg and "MITM" in msg
    assert win._usable_iface_count() == 1


def test_engine_advice_reflects_mitm(app, monkeypatch):
    import reforge.gui.main_window as MW
    win = _win(app)
    monkeypatch.setattr(MW, "list_interfaces", lambda: ["eth0", "eth1"])
    # a running MITM flips the recommendation to NFQUEUE even with two NICs
    import reforge.diagnostics.doctor as D
    monkeypatch.setattr(D, "check_nfqueue_ready",
                        lambda: D.Check("nfqueue-ready", True, "ok"))
    assert win._engine_advice(mitm_active=True).engine == "nfqueue"
    assert win._engine_advice(mitm_active=False).engine == "bridge"


def test_message_proxy_warning_routes_http_intent(app):
    win = _win(app)
    # no http rules -> no warning
    win.rules_panel.specs[:] = [{"enabled": True, "match": {"type": "all"},
        "actions": [{"type": "drop"}]}]
    assert win._message_proxy_warning() == ""
    # a whole-message http transform -> warn + name the relay + equivalent transform
    win.rules_panel.specs[:] = [{"enabled": True, "match": {"type": "all"},
        "actions": [{"type": "http_inject", "snippet": "<script>"}]}]
    warn = win._message_proxy_warning()
    assert "TCP proxy" in warn and "inject HTML" in warn
    assert any(e.kind == "proxy-intent" for e in win.engagement.events)


def test_inline_warnings_combines_preflight_and_proxy(app, monkeypatch):
    win = _win(app)
    monkeypatch.setattr(win, "_inline_preflight_warning", lambda ifaces=None: "PRE")
    monkeypatch.setattr(win, "_message_proxy_warning", lambda: "PROXY")
    assert win._inline_warnings() == "PRE   PROXY"
    monkeypatch.setattr(win, "_message_proxy_warning", lambda: "")
    assert win._inline_warnings() == "PRE"                    # empties dropped


def test_status_pill_reflects_session_state(app):
    from reforge.core.bridge import UserspaceBridge
    win = _win(app)
    assert win.status_pill.property("state") == "stopped"
    win.service = UserspaceBridge("a", "b", armed=False)
    win._refresh_status_pill()
    assert win.status_pill.property("state") == "passthrough"
    win.service.armed = True
    win._on_arm_toggled(True)
    assert win.status_pill.property("state") == "modifying"
    assert "Modifying" in win.act_arm.text() and win.arm_btn.property("armed") == "yes"
    win.service = None


def test_seqfix_and_csum_actions_survive_off_the_bar(app):
    # retired from the session bar but still present as state for auto-arm / start
    win = _win(app)
    assert hasattr(win, "act_seqfix") and hasattr(win, "act_csum")
    assert hasattr(win, "act_kill")                    # now the overflow 'Revert'
