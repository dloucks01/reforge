"""Theme palette + toggle tests (no display needed)."""

from __future__ import annotations

from reforge.gui import theme


def test_palettes_share_keys():
    assert set(theme.DARK) == set(theme.LIGHT)
    assert set(theme.DARK["PROTO"]) == set(theme.LIGHT["PROTO"])


def test_proto_color_falls_back():
    # unknown protocol returns the active text color, not a crash
    assert theme.proto_color("NOPE") == theme._active["TEXT"]


def test_toggle_mode_flips():
    assert theme.toggle_mode() in ("dark", "light")


def test_save_and_load_roundtrip(tmp_path, monkeypatch):
    settings = tmp_path / "ui.json"
    monkeypatch.setattr(theme, "_SETTINGS", settings)
    theme.save_mode("light")
    assert theme.load_mode() == "light"
    theme.save_mode("dark")
    assert theme.load_mode() == "dark"


def test_load_mode_default_when_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(theme, "_SETTINGS", tmp_path / "does-not-exist.json")
    assert theme.load_mode("dark") == "dark"
