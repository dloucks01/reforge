"""Diagnostics & troubleshooting tab (Phase 6).

Sub-tabs: Doctor (self-checks), Health (live counters/rates), Tracer (why a rule
did/didn't fire on a selected packet), Self-test (end-to-end pipeline check),
Logs (tail + diagnostic-bundle export), and the offline Knowledge base.
"""

from __future__ import annotations

from typing import Callable

from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from reforge.diagnostics import bundle, health, kb, selftest, tracer
from reforge.gui import theme

_mono = None


def mono() -> QFont:
    global _mono
    if _mono is None:
        _mono = QFont("JetBrains Mono")
        _mono.setStyleHint(QFont.Monospace)
    return _mono


class DiagnosticsPanel(QWidget):
    def __init__(self, *, get_selected_packet: Callable[[], bytes | None],
                 build_engine: Callable, get_service: Callable,
                 get_bridge_ifaces: Callable[[], list], get_rule_specs: Callable,
                 parent=None):
        super().__init__(parent)
        self._get_packet = get_selected_packet
        self._build_engine = build_engine
        self._get_service = get_service
        self._get_ifaces = get_bridge_ifaces
        self._get_specs = get_rule_specs
        self._meter = health.RateMeter()

        tabs = QTabWidget()
        tabs.addTab(self._doctor_tab(), "Doctor")
        tabs.addTab(self._health_tab(), "Health")
        tabs.addTab(self._tracer_tab(), "Tracer")
        tabs.addTab(self._selftest_tab(), "Self-test")
        tabs.addTab(self._logs_tab(), "Logs")
        tabs.addTab(self._kb_tab(), "Knowledge base")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.addWidget(tabs)
        self.run_doctor()
        self.search_kb()

    # ---- Doctor -------------------------------------------------------------
    def _doctor_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        bar = QHBoxLayout()
        btn = QPushButton("Re-run checks"); btn.clicked.connect(self.run_doctor)
        bar.addWidget(btn); bar.addStretch(1)
        v.addLayout(bar)
        self.doctor_table = QTableWidget(0, 3)
        self.doctor_table.setHorizontalHeaderLabels(["Check", "Status", "Detail / fix"])
        self.doctor_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.doctor_table.setColumnWidth(0, 150)
        v.addWidget(self.doctor_table)
        return w

    def run_doctor(self) -> None:
        from reforge.diagnostics.doctor import run_checks

        rows = run_checks()
        self.doctor_table.setRowCount(0)
        for c in rows:
            r = self.doctor_table.rowCount()
            self.doctor_table.insertRow(r)
            status = QTableWidgetItem("PASS" if c.ok else "FAIL")
            status.setForeground(QBrush(QColor(theme.OK if c.ok else theme.DANGER)))
            detail = c.detail + (f"\nfix: {c.fix}" if (not c.ok and c.fix) else "")
            for col, item in enumerate((QTableWidgetItem(c.name), status,
                                        QTableWidgetItem(detail))):
                self.doctor_table.setItem(r, col, item)
        self.doctor_table.resizeRowsToContents()

    # ---- Health -------------------------------------------------------------
    def _health_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        self.health_view = QPlainTextEdit(); self.health_view.setReadOnly(True)
        self.health_view.setFont(mono())
        v.addWidget(self.health_view)
        return w

    def refresh_health(self) -> None:
        service = self._get_service()
        snap = health.snapshot(service, self._meter)
        lines = [f"running: {snap['running']}"]
        if snap["counters"]:
            lines.append("\ncounters:")
            for k, val in snap["counters"].items():
                rate = snap.get("rates", {}).get(k + "_per_s")
                extra = f"   ({rate:.0f}/s)" if rate else ""
                lines.append(f"  {k:14s} {val}{extra}")
        sysd = snap["system"]
        lines.append(f"\ncpu_count: {sysd.get('cpu_count')}   loadavg: {sysd.get('loadavg')}")
        self.health_view.setPlainText("\n".join(lines))

    # ---- Tracer -------------------------------------------------------------
    def _tracer_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        bar = QHBoxLayout()
        btn = QPushButton("Trace selected packet"); btn.clicked.connect(self.trace_selected)
        bar.addWidget(QLabel("Runs the current rules against the packet selected in Capture."))
        bar.addStretch(1); bar.addWidget(btn)
        v.addLayout(bar)
        self.tracer_view = QPlainTextEdit(); self.tracer_view.setReadOnly(True)
        self.tracer_view.setFont(mono())
        v.addWidget(self.tracer_view)
        return w

    def trace_selected(self) -> None:
        data = self._get_packet()
        if not data:
            self.tracer_view.setPlainText("Select a packet in the Capture tab first.")
            return
        specs = self._get_specs()
        if not specs:
            self.tracer_view.setPlainText("No rules defined — add a rule first.")
            return
        engine = self._build_engine()
        self.tracer_view.setPlainText(tracer.format_trace(tracer.trace(engine, data)))

    # ---- Self-test ----------------------------------------------------------
    def _selftest_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        bar = QHBoxLayout()
        btn = QPushButton("Run self-test"); btn.clicked.connect(self.run_selftest)
        bar.addWidget(QLabel("Injects a marker frame through the pipeline and verifies it."))
        bar.addStretch(1); bar.addWidget(btn)
        v.addLayout(bar)
        self.selftest_view = QPlainTextEdit(); self.selftest_view.setReadOnly(True)
        self.selftest_view.setFont(mono())
        v.addWidget(self.selftest_view)
        return w

    def run_selftest(self) -> None:
        report = selftest.run_selftest()
        head = "SELF-TEST: " + ("PASS" if report.ok else "FAIL")
        lines = [head, ""]
        for s in report.steps:
            lines.append(f"  [{'ok' if s.ok else 'XX'}] {s.name}"
                         + (f" — {s.detail}" if s.detail else ""))
        self.selftest_view.setPlainText("\n".join(lines))

    # ---- Logs / bundle ------------------------------------------------------
    def _logs_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        bar = QHBoxLayout()
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self.refresh_logs)
        export = QPushButton("Export diagnostic bundle"); export.clicked.connect(self.export_bundle)
        bar.addWidget(refresh); bar.addStretch(1); bar.addWidget(export)
        v.addLayout(bar)
        self.log_view = QPlainTextEdit(); self.log_view.setReadOnly(True); self.log_view.setFont(mono())
        v.addWidget(self.log_view)
        return w

    def refresh_logs(self) -> None:
        from reforge.constants import LOG_DIR

        try:
            text = (LOG_DIR / "reforge.log").read_text(errors="replace")
            self.log_view.setPlainText("\n".join(text.splitlines()[-400:]))
        except Exception as exc:
            self.log_view.setPlainText(f"(no log: {exc})")

    def export_bundle(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Export diagnostic bundle",
                                              "reforge-diagnostics.json", "JSON (*.json)")
        if not path:
            return
        service = self._get_service()
        counters = {}
        if service is not None and hasattr(service, "counters"):
            c = service.counters
            counters = c.as_dict() if hasattr(c, "as_dict") else dict(c)
        bundle.write_bundle(path, interfaces=self._get_ifaces(),
                            counters=counters, rules=self._get_specs())
        self.log_view.setPlainText(f"Diagnostic bundle written to {path}")

    # ---- Knowledge base -----------------------------------------------------
    def _kb_tab(self) -> QWidget:
        w = QWidget(); v = QVBoxLayout(w)
        self.kb_search = QLineEdit(); self.kb_search.setPlaceholderText("search symptoms…")
        self.kb_search.textChanged.connect(self.search_kb)
        v.addWidget(self.kb_search)
        self.kb_list = QListWidget(); self.kb_list.currentRowChanged.connect(self._kb_selected)
        v.addWidget(self.kb_list, 1)
        self.kb_detail = QPlainTextEdit(); self.kb_detail.setReadOnly(True)
        v.addWidget(self.kb_detail, 1)
        return w

    def search_kb(self) -> None:
        self._kb_results = kb.search(self.kb_search.text() if hasattr(self, "kb_search") else "")
        self.kb_list.clear()
        for e in self._kb_results:
            self.kb_list.addItem(e.symptom)

    def _kb_selected(self, row: int) -> None:
        if 0 <= row < len(self._kb_results):
            e = self._kb_results[row]
            self.kb_detail.setPlainText(
                f"SYMPTOM: {e.symptom}\n\nCAUSE: {e.cause}\n\nFIX: {e.fix}"
                + (f"\n\nrelated check: {e.check}" if e.check else ""))
