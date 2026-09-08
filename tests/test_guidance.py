"""In-app guidance: section copy, help tooltips, and the intro widgets."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from reforge.gui import guidance as G


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def test_sections_are_well_formed():
    assert G.SECTIONS and isinstance(G.SECTIONS, list)
    for s in G.SECTIONS:
        assert s.get("key") and s.get("title")


def test_help_tooltips_are_nonempty_text():
    assert "BPF" in G.bpf_help_tooltip() or len(G.bpf_help_tooltip()) > 20
    assert len(G.filter_help_tooltip()) > 20


def test_panel_intro_and_wrap(app):
    from PySide6.QtWidgets import QLabel, QWidget

    key = G.SECTIONS[0]["key"]
    clicks = []
    intro = G.PanelIntro(key, on_guide=lambda k: clicks.append(k))
    assert isinstance(intro, QWidget)

    inner = QLabel("panel body")
    wrapped = G.wrap_with_intro(inner, key)
    assert isinstance(wrapped, QWidget)
