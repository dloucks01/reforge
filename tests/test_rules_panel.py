"""RulesPanel + AddRuleDialog: build specs from the UI and drive them offline."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def test_coerce_numbers_and_strings(app):
    from reforge.gui.rules_panel import _coerce
    assert _coerce("80") == 80
    assert _coerce("0x1f") == 31
    assert _coerce("10.0.0.1") == "10.0.0.1"
    assert _coerce("  ") == ""


def _dialog(app, **kw):
    from reforge.gui.rules_panel import AddRuleDialog
    d = AddRuleDialog()
    for attr, val in kw.items():
        w = getattr(d, attr)
        if hasattr(w, "setCurrentText"):
            w.setCurrentText(val)
        else:
            w.setText(val)
    return d


def test_dialog_field_match_set_field_spec(app):
    d = _dialog(app, name="redirect", m_layer="UDP", m_field="dport", m_value="53",
                a_layer="IP", a_field="dst", a_value="10.0.0.9")
    d.m_op.setCurrentText("eq")
    d.a_type.setCurrentText("set_field")
    spec = d.spec()
    assert spec["name"] == "redirect"
    assert spec["match"] == {"type": "field", "layer": "UDP", "field": "dport",
                             "op": "eq", "value": 53}
    assert spec["actions"] == [{"type": "set_field", "layer": "IP",
                                "field": "dst", "value": "10.0.0.9"}]


def test_dialog_blank_layer_means_any_packet(app):
    d = _dialog(app)
    d.a_type.setCurrentText("drop")
    spec = d.spec()
    assert spec["match"] == {"type": "all"} and spec["actions"][0]["type"] == "drop"


def test_dialog_delay_duplicate_and_payload_actions(app):
    d = _dialog(app, a_value="0.25"); d.a_type.setCurrentText("delay")
    assert d.spec()["actions"][0] == {"type": "delay", "seconds": 0.25}

    d = _dialog(app, a_value="3"); d.a_type.setCurrentText("duplicate")
    assert d.spec()["actions"][0] == {"type": "duplicate", "times": 3}

    d = _dialog(app, a_find="admin", a_replace="guest")
    d.a_type.setCurrentText("payload_replace")
    assert d.spec()["actions"][0] == {"type": "payload_replace",
                                      "find": "admin", "replace": "guest"}


def test_panel_add_refresh_remove_and_build_engine(app):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from reforge.core.apply import apply_engine
    from reforge.gui.rules_panel import RulesPanel

    panel = RulesPanel(on_dry_run=lambda: None)
    panel.specs.append({"name": "r1", "enabled": True,
                        "match": {"type": "field", "layer": "TCP", "field": "dport",
                                  "op": "eq", "value": 80},
                        "actions": [{"type": "set_field", "layer": "IP",
                                     "field": "dst", "value": "10.9.9.9"}]})
    panel.refresh(hits={"r1": 4})
    assert panel.table.rowCount() == 1
    assert panel.table.item(0, 1).text() == "r1"
    assert "TCP.dport eq 80" in panel.table.item(0, 2).text()
    assert panel.table.item(0, 4).text() == "4"                 # hit count shown

    # the panel builds a working engine from its specs
    eng = panel.build_engine(dry_run=False)
    res = apply_engine(eng, bytes(Ether() / IP(dst="1.1.1.1") / TCP(dport=80) / b"x"))
    assert Ether(res.out)[IP].dst == "10.9.9.9"

    # remove clears the row
    panel.table.selectRow(0)
    panel.remove_selected()
    assert panel.table.rowCount() == 0 and panel.specs == []
