"""Built-in Guide: one place to learn every section and the filter syntax.

Left column is a clickable index; the right column is a scrollable reference
built from the shared SECTIONS copy plus the filter cheat sheet. scroll_to(key)
lets a panel's 'Guide ›' link jump straight to the relevant section.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from reforge.constants import APP_NAME
from reforge.gui.guidance import FILTER_HELP, SECTIONS


class GuidePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._anchors: dict[str, QWidget] = {}

        root = QHBoxLayout(self)

        # ---- left: index ---------------------------------------------------
        self.index = QListWidget()
        self.index.setMaximumWidth(190)
        self.index.setStyleSheet("QListWidget{border:none;}")
        for s in SECTIONS:
            QListWidgetItem(s["title"], self.index).setData(Qt.UserRole, s["key"])
        QListWidgetItem("Filter syntax", self.index).setData(Qt.UserRole, "_filter")
        self.index.currentItemChanged.connect(
            lambda cur, _prev: cur and self.scroll_to(cur.data(Qt.UserRole)))
        root.addWidget(self.index)

        # ---- right: scrollable content ------------------------------------
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.NoFrame)
        body = QWidget()
        self.col = QVBoxLayout(body)
        self.col.setContentsMargins(16, 12, 16, 24)
        self.col.setSpacing(6)

        title = QLabel(f"{APP_NAME} — Guide")
        title.setStyleSheet("font-size:19px;font-weight:800;")
        self.col.addWidget(title)
        intro = QLabel("Pick a section on the left, or read straight through. Every tab also "
                       "has a one-line intro with its first steps.")
        intro.setWordWrap(True); intro.setStyleSheet("color:palette(mid);")
        self.col.addWidget(intro)
        self.col.addSpacing(8)

        for s in SECTIONS:
            self._add_section(s)
        self._add_filter_help()
        self.col.addStretch(1)

        self.scroll.setWidget(body)
        root.addWidget(self.scroll, 1)

    # ---- rendering ---------------------------------------------------------
    def _heading(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size:15px;font-weight:700;margin-top:10px;")
        return lbl

    def _para(self, text: str, muted: bool = False) -> QLabel:
        lbl = QLabel(text)
        lbl.setWordWrap(True)
        lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
        if muted:
            lbl.setStyleSheet("color:palette(mid);")
        return lbl

    def _add_section(self, s: dict) -> None:
        anchor = QWidget()
        av = QVBoxLayout(anchor); av.setContentsMargins(0, 0, 0, 0); av.setSpacing(3)
        av.addWidget(self._heading(s["title"]))
        av.addWidget(self._para(s["blurb"]))
        if s.get("when"):
            av.addWidget(self._para("When: " + s["when"], muted=True))
        if s.get("steps"):
            steps = "".join(f"<li>{x}</li>" for x in s["steps"])
            av.addWidget(self._para(f"<b>Steps</b><ol style='margin:2px 0 2px 0;'>{steps}</ol>"))
        if s.get("tips"):
            tips = "".join(f"<li>{x}</li>" for x in s["tips"])
            av.addWidget(self._para(f"<b>Tips</b><ul style='margin:2px 0 2px 0;'>{tips}</ul>"))
        self._anchors[s["key"]] = anchor
        self.col.addWidget(anchor)

    def _add_filter_help(self) -> None:
        anchor = QWidget()
        av = QVBoxLayout(anchor); av.setContentsMargins(0, 0, 0, 0); av.setSpacing(3)
        av.addWidget(self._heading(FILTER_HELP["title"]))
        av.addWidget(self._para(FILTER_HELP["grammar"]))
        av.addWidget(self._para(FILTER_HELP["ops"]))
        ex = "".join(f"<li><code>{x}</code></li>" for x in FILTER_HELP["examples"])
        av.addWidget(self._para(f"<b>Examples</b><ul style='margin:2px 0 2px 0;'>{ex}</ul>"))
        av.addWidget(self._para(FILTER_HELP["note"], muted=True))
        self._anchors["_filter"] = anchor
        self.col.addWidget(anchor)

    # ---- navigation --------------------------------------------------------
    def scroll_to(self, key: str) -> None:
        w = self._anchors.get(key)
        if w is not None:
            self.scroll.ensureWidgetVisible(w, 0, 0)
