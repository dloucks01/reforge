"""Remembered settings — persist last-used inputs between runs.

A thin wrapper over QSettings (writes ~/.config/Reforge/Reforge.conf on Linux),
plus type-dispatching save/load so a panel can hand a {key: widget} map and have
its fields remembered without bespoke code per field. Values are per-operator and
local; nothing sensitive (no captures, creds, or keys) is stored here.
"""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QLineEdit,
    QPlainTextEdit,
    QSpinBox,
)

ORG = "Reforge"
APP = "Reforge"


def settings() -> QSettings:
    return QSettings(ORG, APP)


def save_widget(s: QSettings, key: str, w) -> None:
    if isinstance(w, QLineEdit):
        s.setValue(key, w.text())
    elif isinstance(w, QPlainTextEdit):
        s.setValue(key, w.toPlainText())
    elif isinstance(w, QComboBox):
        s.setValue(key, w.currentText())
    elif isinstance(w, QSpinBox):
        s.setValue(key, int(w.value()))
    elif isinstance(w, QCheckBox):
        s.setValue(key, bool(w.isChecked()))


def load_widget(s: QSettings, key: str, w) -> None:
    if not s.contains(key):
        return
    val = s.value(key)
    try:
        if isinstance(w, QLineEdit):
            w.setText(str(val))
        elif isinstance(w, QPlainTextEdit):
            w.setPlainText(str(val))
        elif isinstance(w, QComboBox):
            text = str(val)
            if w.findText(text) >= 0:            # only restore a still-valid choice
                w.setCurrentText(text)
        elif isinstance(w, QSpinBox):
            w.setValue(int(val))
        elif isinstance(w, QCheckBox):
            w.setChecked(str(val).lower() in ("1", "true", "yes"))
    except (ValueError, TypeError):
        pass                                     # ignore a corrupt stored value


def save_all(mapping: dict) -> None:
    s = settings()
    for key, w in mapping.items():
        save_widget(s, key, w)
    s.sync()


def load_all(mapping: dict) -> None:
    s = settings()
    for key, w in mapping.items():
        load_widget(s, key, w)
