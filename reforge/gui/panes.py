"""Pane area — one or two side-by-side workspaces, plus detach-to-window.

The operator needs to see two things at once (the stream while editing an
intercept, two flows, a workspace on a second monitor). Workspaces are
single-instance widgets, so a given workspace lives in exactly one place: a pane,
a detached window, or the hidden park. Moving it anywhere pulls it from wherever
it was. The nav rail drives the active pane.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSplitter,
    QStackedWidget,
    QToolButton,
    QVBoxLayout,
    QWidget,
)


class WorkspacePane(QFrame):
    """A framed slot that hosts one workspace widget, with a slim header."""

    activated = Signal(object)
    split_requested = Signal(object)
    detach_requested = Signal(object)
    close_requested = Signal(object)

    def __init__(self, area, parent=None):
        super().__init__(parent)
        self.setObjectName("wsPane")
        self.area = area
        self.key: str | None = None

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self.head = QFrame()
        self.head.setObjectName("paneHead")
        hl = QHBoxLayout(self.head)
        hl.setContentsMargins(9, 3, 6, 3)
        hl.setSpacing(4)
        self.title = QLabel("")
        self.title.setObjectName("paneTitle")
        hl.addWidget(self.title)
        hl.addStretch(1)
        self.btn_split = self._btn("⊟", "Split — show a second workspace",
                                   lambda: self.split_requested.emit(self))
        self.btn_detach = self._btn("⤢", "Detach to its own window",
                                    lambda: self.detach_requested.emit(self))
        self.btn_close = self._btn("✕", "Close this pane",
                                   lambda: self.close_requested.emit(self))
        for b in (self.btn_split, self.btn_detach, self.btn_close):
            hl.addWidget(b)
        outer.addWidget(self.head)

        self.body = QVBoxLayout()
        self.body.setContentsMargins(0, 0, 0, 0)
        holder = QWidget()
        holder.setLayout(self.body)
        outer.addWidget(holder, 1)

    def _btn(self, glyph, tip, cb) -> QToolButton:
        b = QToolButton()
        b.setObjectName("paneBtn")
        b.setText(glyph)
        b.setToolTip(tip)
        b.clicked.connect(cb)
        return b

    def mousePressEvent(self, e) -> None:
        self.activated.emit(self)
        super().mousePressEvent(e)

    def set_content(self, key: str, title: str, widget: QWidget) -> None:
        self.key = key
        self.title.setText(title)
        self.body.addWidget(widget)
        widget.setVisible(True)   # the park (QStackedWidget) hides non-current pages

    def take_content(self) -> QWidget | None:
        w = self.body.itemAt(0).widget() if self.body.count() else None
        if w is not None:
            self.body.removeWidget(w)
        self.key = None
        return w

    def set_can_close(self, on: bool) -> None:
        self.btn_close.setVisible(on)

    def set_active(self, on: bool) -> None:
        for w in (self, self.head, self.title):
            w.setProperty("active", "true" if on else "false")
            w.style().unpolish(w)
            w.style().polish(w)


class _DetachWindow(QWidget):
    closed = Signal(str)

    def __init__(self, key: str, title: str):
        super().__init__()
        self.key = key
        self.setWindowTitle(f"Reforge — {title}")
        self.resize(720, 520)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self._body = lay

    def set_widget(self, w: QWidget) -> None:
        self._body.addWidget(w)
        w.setVisible(True)

    def take_widget(self) -> QWidget | None:
        w = self._body.itemAt(0).widget() if self._body.count() else None
        if w is not None:
            self._body.removeWidget(w)
        return w

    def closeEvent(self, e) -> None:
        self.closed.emit(self.key)
        super().closeEvent(e)


class PaneArea(QWidget):
    """Holds up to two workspace panes side by side, plus detached windows."""

    active_changed = Signal(str)   # key now shown in the active pane

    def __init__(self, workspaces: dict[str, QWidget], titles: dict[str, str], parent=None):
        super().__init__(parent)
        self.workspaces = workspaces
        self.titles = titles
        self._detached: dict[str, _DetachWindow] = {}

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self._splitter = QSplitter(Qt.Horizontal)
        lay.addWidget(self._splitter)

        # hidden park holds every workspace not currently placed
        self._park = QStackedWidget()
        self._park.hide()
        for w in workspaces.values():
            self._park.addWidget(w)

        self.panes: list[WorkspacePane] = []
        self.active: WorkspacePane | None = None
        self._add_pane()

    # ---- pane management ----------------------------------------------------
    def _add_pane(self) -> WorkspacePane:
        pane = WorkspacePane(self)
        pane.activated.connect(self._on_pane_activated)
        pane.split_requested.connect(lambda p: self.split())
        pane.detach_requested.connect(lambda p: self.detach(p.key))
        pane.close_requested.connect(self.close_pane)
        self._splitter.addWidget(pane)
        self.panes.append(pane)
        self._sync_close_buttons()
        return pane

    def _sync_close_buttons(self) -> None:
        for p in self.panes:
            p.set_can_close(len(self.panes) > 1)

    def _refresh_active(self) -> None:
        for p in self.panes:
            p.set_active(p is self.active)

    def _park_widget(self, w: QWidget) -> None:
        if w is not None:
            self._park.addWidget(w)  # reparents into the hidden park

    def _pane_showing(self, key: str) -> WorkspacePane | None:
        for p in self.panes:
            if p.key == key:
                return p
        return None

    def show_in(self, pane: WorkspacePane, key: str) -> None:
        """Place workspace `key` into `pane`, pulling it from wherever it is.

        If another pane already shows `key`, the two panes swap workspaces, so no
        pane is ever left empty."""
        if pane.key == key:
            self.active = pane
            self._refresh_active()
            self.active_changed.emit(key)
            return
        if key in self._detached:                    # bring it back from a window
            win = self._detached.pop(key)
            self._park_widget(win.take_widget())
            win.close()

        cur_key = pane.key
        cur_w = pane.take_content()
        other = self._pane_showing(key)
        if other is not None and other is not pane and cur_key in self.workspaces:
            other.take_content()
            other.set_content(cur_key, self.titles.get(cur_key, cur_key),
                              self.workspaces[cur_key])   # swap
        elif cur_w is not None:
            self._park_widget(cur_w)                      # park what this pane had
        pane.set_content(key, self.titles.get(key, key), self.workspaces[key])
        self.active = pane
        self._refresh_active()
        self.active_changed.emit(key)

    def set_active_workspace(self, key: str) -> None:
        pane = self.active or (self.panes[0] if self.panes else self._add_pane())
        self.show_in(pane, key)

    def split(self) -> None:
        if len(self.panes) >= 2:
            return
        pane = self._add_pane()
        # pick a workspace not already shown for the new pane
        shown = {p.key for p in self.panes}
        nxt = next((k for k in self.workspaces if k not in shown), None)
        if nxt is not None:
            self.show_in(pane, nxt)
        self._splitter.setSizes([1, 1])

    def close_pane(self, pane: WorkspacePane) -> None:
        if len(self.panes) <= 1:
            return
        self._park_widget(pane.take_content())
        self.panes.remove(pane)
        pane.setParent(None)
        pane.deleteLater()
        self.active = self.panes[0]
        self._sync_close_buttons()
        self._refresh_active()

    def detach(self, key: str | None) -> None:
        if not key or key in self._detached:
            return
        pane = self._pane_showing(key)
        if pane is None:
            return
        w = pane.take_content()
        # the pane falls back to another workspace (or empties)
        shown = {p.key for p in self.panes if p is not pane}
        fallback = next((k for k in self.workspaces if k not in shown and k != key), None)
        if fallback is not None:
            pane.set_content(fallback, self.titles.get(fallback, fallback),
                             self.workspaces[fallback])
        win = _DetachWindow(key, self.titles.get(key, key))
        win.set_widget(w)
        win.closed.connect(self._on_detached_closed)
        self._detached[key] = win
        win.show()

    def _on_detached_closed(self, key: str) -> None:
        win = self._detached.pop(key, None)
        if win is None:
            return
        w = win.take_widget()
        self._park_widget(w)   # back to the park; nav can re-show it

    def _on_pane_activated(self, pane: WorkspacePane) -> None:
        self.active = pane
        self._refresh_active()
        if pane.key:
            self.active_changed.emit(pane.key)

    def current_key(self, pane_index: int = 0) -> str | None:
        if 0 <= pane_index < len(self.panes):
            return self.panes[pane_index].key
        return None
