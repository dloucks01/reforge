"""Left navigation rail — the primary way to move between workspaces.

Replaces the old tab strip + floating docks. A compact vertical list of the six
workspaces; clicking one emits `switched(key)`. Keyboard focusable, single active
at a time. Styling lives in the app QSS (`#navRail`, `#navBtn`).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# (key, label) for each workspace, in rail order
SECTIONS: list[tuple[str, str]] = [
    ("live", "Live"),
    ("recon", "Recon"),
    ("craft", "Craft"),
    ("attack", "Attack"),
    ("automate", "Automate"),
    ("system", "System"),
]


class NavRail(QWidget):
    switched = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("navRail")
        self._buttons: dict[str, QPushButton] = {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(6, 8, 6, 8)
        lay.setSpacing(2)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        for key, label in SECTIONS:
            b = QPushButton(label)
            b.setObjectName("navBtn")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.switched.emit(k))
            self._group.addButton(b)
            lay.addWidget(b)
            self._buttons[key] = b

        lay.addStretch(1)
        self._note = QLabel("")
        self._note.setObjectName("navNote")
        self._note.setWordWrap(True)
        lay.addWidget(self._note)

    def set_active(self, key: str) -> None:
        b = self._buttons.get(key)
        if b is not None:
            b.setChecked(True)

    def set_note(self, text: str) -> None:
        self._note.setText(text)
