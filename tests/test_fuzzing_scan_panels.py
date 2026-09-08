"""FuzzingPanel seed/preview + ScanPanel port presets (offline, no network)."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


# ---- FuzzingPanel ---------------------------------------------------------
def _fpanel(app, builder_bytes=None, selected=None):
    from reforge.gui.fuzzing_panel import FuzzingPanel
    return FuzzingPanel(get_builder_bytes=lambda: builder_bytes,
                        get_selected_packet=lambda: selected)


def test_set_seed_requires_data(app):
    p = _fpanel(app)
    p._set_seed(None, "builder packet")
    assert "No seed" in p.status.text()


def test_seed_from_builder_and_preview(app):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    seed = bytes(Ether() / IP(dst="10.0.0.9") / TCP(dport=80) / b"GET / HTTP/1.0\r\n\r\n")
    p = _fpanel(app, builder_bytes=seed)
    p._seed_builder()
    assert p._seed == seed and "Seed set" in p.status.text()

    p.preview()                                       # deterministic (seeded RNG)
    text = p.view.toPlainText()
    assert "Preview of generated variants" in text
    assert text.count("\n") >= 8                      # 8 variants previewed
    assert "Previewed 8 variants" in p.status.text()


def test_preview_without_seed_prompts(app):
    p = _fpanel(app)
    p.preview()
    assert "Pick a seed" in p.status.text()


def test_strategies_reflect_checkboxes(app):
    p = _fpanel(app)
    # unchecking all strategy boxes yields an empty selection
    for cb, _s in p.strat_boxes.values():
        cb.setChecked(False)
    assert p._strategies() == []
    first = next(iter(p.strat_boxes.values()))[0]
    first.setChecked(True)
    assert len(p._strategies()) == 1


# ---- ScanPanel ------------------------------------------------------------
def test_scan_port_preset_fills_ports(app):
    from reforge.gui.scan_panel import _PORT_SETS, ScanPanel

    p = ScanPanel()
    assert _PORT_SETS, "expected at least one port preset"
    p._apply_port_preset(1)                            # first real preset
    assert p.ports.text() == _PORT_SETS[0][1]
    assert p.port_preset.currentIndex() == 0           # resets like a menu


def test_scan_port_preset_index_zero_is_noop(app):
    from reforge.gui.scan_panel import ScanPanel
    p = ScanPanel()
    before = p.ports.text()
    p._apply_port_preset(0)                             # the "Ports…" header
    assert p.ports.text() == before
