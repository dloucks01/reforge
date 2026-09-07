"""Scenario runner tab — load a scripted engagement, run it, show/save the report."""

from __future__ import annotations

import threading

from PySide6.QtCore import QTimer
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class ScenarioPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._spec = None
        self._report = None
        self._worker = None

        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        load = QPushButton("Load scenario…"); load.clicked.connect(self._load)
        self.file_lbl = QLabel("no scenario loaded")
        self.dry = QCheckBox("dry-run"); self.dry.setChecked(True)
        self.run_btn = QPushButton("Run"); self.run_btn.clicked.connect(self._run)
        bar.addWidget(load); bar.addWidget(self.file_lbl, 1)
        bar.addWidget(self.dry); bar.addWidget(self.run_btn)
        root.addLayout(bar)

        mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace)
        self.view = QPlainTextEdit(); self.view.setReadOnly(True); self.view.setFont(mono)
        root.addWidget(self.view, 1)

        save = QHBoxLayout()
        self.passphrase = QLineEdit(); self.passphrase.setEchoMode(QLineEdit.Password)
        self.passphrase.setPlaceholderText("passphrase to encrypt the saved report (optional)")
        btn_json = QPushButton("Save report…"); btn_json.clicked.connect(self._save)
        save.addWidget(QLabel("Encrypt:")); save.addWidget(self.passphrase)
        save.addStretch(1); save.addWidget(btn_json)
        root.addLayout(save)

        self.status = QLabel("Load a scenario (.json / .yaml) to begin.")
        root.addWidget(self.status)

        self._poll = QTimer(self); self._poll.setInterval(300)
        self._poll.timeout.connect(self._check)

    def _load(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load scenario", "",
                                              "Scenario (*.json *.yaml *.yml)")
        if not path:
            return
        from reforge.scenario.runner import load_scenario

        try:
            self._spec = load_scenario(path)
        except Exception as exc:
            QMessageBox.critical(self, "Scenario error", str(exc)); return
        self.file_lbl.setText(f"{self._spec.get('name', path)}  ({len(self._spec.get('steps', []))} steps)")
        self.status.setText("Loaded. Review dry-run before a live run.")

    def _run(self):
        if self._spec is None:
            self.status.setText("Load a scenario first."); return
        if self._worker and self._worker.is_alive():
            return
        from reforge.scenario.runner import ScenarioRunner

        dry = self.dry.isChecked()
        spec = self._spec

        def work():
            self._report = ScenarioRunner(dry_run=dry).run(spec)

        self._report = None
        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()
        self._poll.start()
        self.run_btn.setEnabled(False)
        self.status.setText(f"Running ({'dry-run' if dry else 'LIVE'})…")

    def _check(self):
        if self._worker and self._worker.is_alive():
            return
        self._poll.stop()
        self.run_btn.setEnabled(True)
        if self._report is not None:
            self.view.setPlainText(self._report.to_markdown())
            s = self._report
            self.status.setText(f"Done — {len(s.hosts)} host(s), {len(s.credentials)} cred(s).")

    def _save(self):
        if self._report is None:
            self.status.setText("Run a scenario first."); return
        path, _ = QFileDialog.getSaveFileName(self, "Save report", "engagement-report.md",
                                              "Markdown/JSON (*.md *.json)")
        if not path:
            return
        text = self._report.to_json() if path.endswith(".json") else self._report.to_markdown()
        pw = self.passphrase.text().strip()
        from pathlib import Path

        if pw:
            from reforge.core.vault import encrypt_bytes

            Path(path).write_bytes(encrypt_bytes(text.encode(), pw))
            self.status.setText(f"Encrypted report saved -> {path}")
        else:
            Path(path).write_text(text)
            self.status.setText(f"Report saved -> {path}")
