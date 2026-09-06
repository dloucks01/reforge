"""Main window skeleton (PySide6).

Phase 0 stands up the shell and docks named in PLAN.md section 5 so the layout
is real and navigable. Widgets are placeholders wired to live data in later
phases.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDockWidget,
    QLabel,
    QMainWindow,
    QPlainTextEdit,
    QTableWidget,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QWidget,
)

from reforge.constants import APP_NAME, TAGLINE, VERSION
from reforge.diagnostics.doctor import run_checks


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {VERSION} — {TAGLINE}")
        self.resize(1280, 800)

        self._build_toolbar()
        self._build_center()
        self._build_docks()
        self.statusBar().showMessage("Pass-through (not armed)")

    def _build_toolbar(self) -> None:
        tb = QToolBar("main")
        tb.addWidget(QLabel("  Interface: [ none ]   Mode: userspace-bridge   Backend: af_packet   "))
        tb.addAction("Start")
        tb.addAction("Stop")
        tb.addAction("Kill-switch")
        self.addToolBar(tb)

    def _build_center(self) -> None:
        tabs = QTabWidget()

        live = QTableWidget(0, 5)
        live.setHorizontalHeaderLabels(["Time", "Source", "Dest", "Proto", "Info"])
        tabs.addTab(live, "Live capture")

        intercept = QTableWidget(0, 4)
        intercept.setHorizontalHeaderLabels(["Held", "Source", "Dest", "Proto"])
        tabs.addTab(intercept, "Intercept queue")

        tabs.addTab(QWidget(), "Packet builder")
        self.setCentralWidget(tabs)

    def _build_docks(self) -> None:
        # Detail: protocol tree + hex (right)
        detail = QDockWidget("Packet detail", self)
        detail.setWidget(QTreeWidget())
        self.addDockWidget(Qt.RightDockWidgetArea, detail)

        # Session/rules/library (left)
        left = QDockWidget("Session", self)
        left.setWidget(QTreeWidget())
        self.addDockWidget(Qt.LeftDockWidgetArea, left)

        # Diagnostics (bottom) — populated from the Doctor at startup
        diag = QDockWidget("Diagnostics", self)
        log_view = QPlainTextEdit()
        log_view.setReadOnly(True)
        for c in run_checks():
            log_view.appendPlainText(f"[{'PASS' if c.ok else 'FAIL'}] {c.name}: {c.detail}")
        diag.setWidget(log_view)
        self.addDockWidget(Qt.BottomDockWidgetArea, diag)
