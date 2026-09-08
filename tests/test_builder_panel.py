"""BuilderPanel: layer stack editing, field edits, and byte (de)serialization."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def _panel(app):
    from reforge.gui.builder_panel import BuilderPanel
    return BuilderPanel()


def test_add_remove_and_clear_layers(app):
    p = _panel(app)
    p.layer_combo.setCurrentText("Ether"); p._add_layer()
    p.layer_combo.setCurrentText("IP"); p._add_layer()
    assert [l["layer"] for l in p.layers] == ["Ether", "IP"]
    assert p.stack.count() == 2
    p.stack.setCurrentRow(1); p._remove_layer()
    assert [l["layer"] for l in p.layers] == ["Ether"]
    p._clear()
    assert p.layers == [] and p.stack.count() == 0


def test_move_reorders_layers(app):
    p = _panel(app)
    for layer in ("Ether", "IP", "TCP"):
        p.layer_combo.setCurrentText(layer); p._add_layer()
    p.stack.setCurrentRow(2)
    p._move(-1)                                   # TCP up one
    assert [l["layer"] for l in p.layers] == ["Ether", "TCP", "IP"]


def test_field_edit_reflected_in_bytes(app):
    from scapy.layers.inet import IP
    from scapy.layers.l2 import Ether

    p = _panel(app)
    p.layer_combo.setCurrentText("Ether"); p._add_layer()
    p.layer_combo.setCurrentText("IP"); p._add_layer()
    p.layers[1]["fields"]["dst"] = "10.7.7.7"      # set a field directly
    data = p._current_bytes()
    assert data is not None
    assert Ether(data)[IP].dst == "10.7.7.7"


def test_load_bytes_roundtrips_into_layers(app):
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    raw = bytes(Ether() / IP(dst="10.1.2.3") / UDP(dport=53))
    p = _panel(app)
    p.load_bytes(raw)
    names = [l["layer"] for l in p.layers]
    assert names[:3] == ["Ether", "IP", "UDP"]
    # and it rebuilds to a packet addressed the same way
    out = p._current_bytes()
    assert Ether(out)[IP].dst == "10.1.2.3"
