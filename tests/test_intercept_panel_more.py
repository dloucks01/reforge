"""InterceptPanel interactions: presets, filter/search, field edit, apply-to-all,
sent log, and send-to-builder."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def _panel(app):
    from reforge.gui.intercept_panel import InterceptPanel
    return InterceptPanel()


def _held(app, data, kind="packet"):
    from reforge.core.intercept import InterceptQueue
    p = _panel(app)
    q = InterceptQueue()
    p.set_queue(q)
    out = {}
    q.hold("ifa", data, lambda o: out.__setitem__("v", o), flow_key=("f", 1),
           kind=kind, meta={"summary": "s", "from_client": True})
    p.refresh_pending()
    p.table.selectRow(0)
    p._on_select()
    return p, q, out


def _frame(load=b"user=admin"):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    return bytes(Ether() / IP(dst="10.0.0.2") / TCP(dport=80) / load)


# ---- filter / preset / search ---------------------------------------------
def test_apply_filter_enabled_empty_holds_all(app):
    from reforge.rules.matchers import AllMatch
    p = _panel(app)
    got = {}
    p.on_filter = lambda m, t: got.update(m=m, t=t)
    p.enable_check.setChecked(True)
    p.filter_edit.setText("")
    p._apply_filter()
    assert isinstance(got["m"], AllMatch) and "Holding" in p.filter_status.text()


def test_apply_filter_disabled_clears(app):
    p = _panel(app)
    got = {}
    p.on_filter = lambda m, t: got.update(m=m, t=t)
    p.enable_check.setChecked(False)
    p._apply_filter()
    assert got["m"] is None and "off" in p.filter_status.text().lower()


def test_apply_filter_bad_expression_shows_error(app):
    p = _panel(app)
    p.on_filter = lambda m, t: None
    p.enable_check.setChecked(True)
    p.filter_edit.setText("TCP.dport ===== nonsense")
    p._apply_filter()
    assert "error" in p.filter_status.text().lower()


def test_preset_fills_and_installs_filter(app):
    p = _panel(app)
    got = {}
    p.on_filter = lambda m, t: got.update(m=m, t=t)
    p._apply_preset(1)
    assert p.enable_check.isChecked() and p.filter_edit.text()
    assert got.get("m") is not None and p.preset_combo.currentIndex() == 0


def test_search_hides_non_matching_rows(app):
    p, q, _ = _held(app, _frame(b"user=admin"))
    q.hold("ifa", _frame(b"other=data"), lambda o: None, flow_key=("f", 2),
           kind="packet", meta={"summary": "s", "from_client": True})
    p.refresh_pending()
    p.search_edit.setText("zzz-nomatch")
    p._apply_search()
    hidden = [p.table.isRowHidden(r) for r in range(p.table.rowCount())]
    assert all(hidden)                                  # nothing matches
    p.search_edit.setText("")
    p._apply_search()
    assert not any(p.table.isRowHidden(r) for r in range(p.table.rowCount()))


# ---- editing --------------------------------------------------------------
def test_field_edit_updates_work_bytes(app):
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    from reforge.gui.intercept_panel import _LAYER_FIELD

    p, _q, _ = _held(app, _frame())
    p._rebuild_tree()
    # find the IP.dst tree item and edit it
    target = None
    for i in range(p.tree.topLevelItemCount()):
        parent = p.tree.topLevelItem(i)
        for j in range(parent.childCount()):
            child = parent.child(j)
            if child.data(0, _LAYER_FIELD) == ("IP", "dst"):
                target = child
    assert target is not None
    p.tree.blockSignals(True)                           # avoid the auto itemChanged
    target.setText(1, "10.9.9.9")
    p.tree.blockSignals(False)
    p._on_field_edited(target, 1)
    assert Ether(p._work)[IP].dst == "10.9.9.9"


def test_view_toggle_hex_ascii(app):
    p, _, _ = _held(app, _frame())
    p._on_view_changed("ASCII")
    assert p._view == "ascii"
    p._on_view_changed("Hex")
    assert p._view == "hex"


def test_apply_to_all_promotes_and_forwards(app):
    p, _q, out = _held(app, _frame(b"user=admin"))
    promoted = {}
    p.on_promote = lambda orig, edited: promoted.setdefault("msg", "Transform added") or "Transform added"
    # edit the payload in the hex/ascii editor
    p.view_combo.setCurrentText("ASCII")
    txt = p.hex_edit.toPlainText().replace("admin", "guest")
    p.hex_edit.setPlainText(txt)
    p._apply_to_all()
    assert "msg" in promoted                            # promote callback fired
    assert out.get("v", b"").endswith(b"user=guest")    # current packet forwarded edited
    assert p.enable_check.isChecked() is False          # holding turned off


# ---- sent log + send-to-builder -------------------------------------------
def test_resolve_logs_to_sent_table(app):
    p, _q, _out = _held(app, _frame())
    p._resolve("forward")
    assert p.sent_table.rowCount() == 1
    p.sent_table.selectRow(0)
    p._on_sent_select()                                 # must not raise


def test_send_to_builder_callback(app):
    p, _q, _ = _held(app, _frame())
    got = {}
    p.on_send_to_builder = lambda data: got.setdefault("data", data)
    p._send_to_builder(_frame())
    assert got.get("data") == _frame()


def test_hex_edit_recomputes_checksums_so_packet_is_valid(app):
    """A hex/ASCII payload edit must produce a packet with valid checksums, or the
    inline receiver would drop it (field edits already rebuild; raw edits didn't)."""
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    orig = bytes(Ether() / IP() / TCP(dport=80) / Raw(b"AAAA"))
    p, _q, out = _held(app, orig)
    # edit the payload in ASCII view (raw bytes, no scapy rebuild on the operator side)
    p.view_combo.setCurrentText("ASCII")
    txt = p.hex_edit.toPlainText().replace("AAAA", "BBBB")
    p.hex_edit.setPlainText(txt)
    p._resolve("modify")

    forwarded = out["v"]
    assert forwarded.endswith(b"BBBB")                 # the edit is present
    # and the checksums are valid: re-dissecting and re-serializing is a no-op
    pkt = Ether(forwarded)
    good_ip = pkt[IP].chksum
    good_tcp = pkt[TCP].chksum
    del pkt[IP].chksum, pkt[TCP].chksum
    fixed = Ether(bytes(pkt))                            # scapy recomputes here
    assert fixed[IP].chksum == good_ip and fixed[TCP].chksum == good_tcp
