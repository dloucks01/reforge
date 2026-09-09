"""Rules panel: build a match→action rule set and dry-run it over the capture.

Phase 2 scope. Live inline enforcement runs via the NFQUEUE runner / userspace
bridge; here the operator composes rules and validates them against captured
packets (shadow / dry-run) before arming — exactly the safe-preview workflow.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.gui import theme
from reforge.rules import spec as S

RULE_COLUMNS = ["On", "Name", "Match", "Actions", "Hits"]
OPS = ["eq", "ne", "lt", "le", "gt", "ge", "in", "contains", "cidr"]
ACTION_TYPES = ["drop", "set_field", "delay", "payload_replace", "duplicate", "hold",
                "fuzz", "strip_starttls", "http_sslstrip", "http_strip_encoding",
                "http_inject", "http_replace_body", "http_strip_cookie",
                "http_remove_sec_headers"]


def _coerce(value: str):
    v = value.strip()
    if v == "":
        return v
    try:
        return int(v, 0)
    except ValueError:
        return v


class AddRuleDialog(QDialog):
    def __init__(self, parent=None, default_name="rule"):
        super().__init__(parent)
        self.setWindowTitle("Add rule")
        self.setMinimumWidth(420)
        form = QFormLayout(self)

        self.name = QLineEdit(default_name)
        form.addRow("Name", self.name)

        form.addRow(self._section("Match  (leave layer blank = any packet)"))
        self.m_layer = QLineEdit(); self.m_layer.setPlaceholderText("e.g. TCP")
        self.m_field = QLineEdit(); self.m_field.setPlaceholderText("e.g. dport")
        self.m_op = QComboBox(); self.m_op.addItems(OPS)
        self.m_value = QLineEdit(); self.m_value.setPlaceholderText("e.g. 80 or 10.0.0.0/24")
        form.addRow("Layer", self.m_layer)
        form.addRow("Field", self.m_field)
        form.addRow("Op", self.m_op)
        form.addRow("Value", self.m_value)

        form.addRow(self._section("Action"))
        self.a_type = QComboBox(); self.a_type.addItems(ACTION_TYPES)
        form.addRow("Type", self.a_type)
        self.a_layer = QLineEdit(); self.a_layer.setPlaceholderText("set_field: layer e.g. IP")
        self.a_field = QLineEdit(); self.a_field.setPlaceholderText("set_field: field e.g. dst")
        self.a_value = QLineEdit(); self.a_value.setPlaceholderText("set_field: value / delay secs / duplicate times")
        self.a_find = QLineEdit(); self.a_find.setPlaceholderText("payload_replace: find")
        self.a_replace = QLineEdit(); self.a_replace.setPlaceholderText("payload_replace: replace")
        for lbl, w in (("layer/field", self.a_layer), ("field", self.a_field),
                       ("value/secs/times", self.a_value),
                       ("find", self.a_find), ("replace", self.a_replace)):
            form.addRow(lbl, w)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _section(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet(f"color: {theme.ACCENT}; font-weight: 700; margin-top: 6px;")
        return lbl

    def spec(self) -> dict:
        layer = self.m_layer.text().strip()
        if layer:
            match = {"type": "field", "layer": layer, "field": self.m_field.text().strip(),
                     "op": self.m_op.currentText(), "value": _coerce(self.m_value.text())}
        else:
            match = {"type": "all"}

        t = self.a_type.currentText()
        if t == "set_field":
            action = {"type": "set_field", "layer": self.a_layer.text().strip(),
                      "field": self.a_field.text().strip(), "value": _coerce(self.a_value.text())}
        elif t == "delay":
            action = {"type": "delay", "seconds": float(self.a_value.text() or 0)}
        elif t == "duplicate":
            action = {"type": "duplicate", "times": int(self.a_value.text() or 1)}
        elif t == "payload_replace":
            action = {"type": "payload_replace", "find": self.a_find.text(),
                      "replace": self.a_replace.text()}
        elif t == "fuzz":
            action = {"type": "fuzz", "mutations": int(self.a_value.text() or 4)}
        elif t == "http_inject":
            action = {"type": "http_inject", "snippet": self.a_value.text()}
        elif t == "http_replace_body":
            action = {"type": "http_replace_body", "body": self.a_value.text(),
                      "content_type": self.a_find.text() or None}
        elif t.startswith("http_"):
            action = {"type": t}
        else:  # drop / hold
            action = {"type": t}

        return {"name": self.name.text().strip() or "rule", "enabled": True,
                "match": match, "actions": [action]}


class RulesPanel(QWidget):
    def __init__(self, on_dry_run: Callable[[], None], parent=None):
        super().__init__(parent)
        self.specs: list[dict] = []
        self._on_dry_run = on_dry_run
        self.setMinimumWidth(360)

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)

        bar = QHBoxLayout()
        add = QPushButton("Add rule"); add.clicked.connect(self.add_rule)
        rm = QPushButton("Remove"); rm.clicked.connect(self.remove_selected)
        dry = QPushButton("Dry-run over capture"); dry.clicked.connect(self._on_dry_run)
        bar.addWidget(add); bar.addWidget(rm); bar.addStretch(1); bar.addWidget(dry)
        root.addLayout(bar)

        self.table = QTableWidget(0, len(RULE_COLUMNS))
        self.table.setHorizontalHeaderLabels(RULE_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        for col, w in ((0, 40), (1, 130), (4, 60)):
            self.table.setColumnWidth(col, w)
        root.addWidget(self.table)

    def add_rule(self) -> None:
        dlg = AddRuleDialog(self, default_name=f"rule-{len(self.specs) + 1}")
        if dlg.exec() == QDialog.Accepted:
            self.specs.append(dlg.spec())
            self.refresh()

    def remove_selected(self) -> None:
        rows = sorted((i.row() for i in self.table.selectionModel().selectedRows()), reverse=True)
        for r in rows:
            if 0 <= r < len(self.specs):
                del self.specs[r]
        self.refresh()

    def refresh(self, hits: dict[str, int] | None = None) -> None:
        hits = hits or {}
        self.table.setRowCount(0)
        for s in self.specs:
            r = self.table.rowCount()
            self.table.insertRow(r)
            on = QTableWidgetItem("✓" if s.get("enabled", True) else "")
            on.setTextAlignment(Qt.AlignCenter)
            name = QTableWidgetItem(s["name"])
            match = QTableWidgetItem(S.match_summary(s["match"]))
            acts = QTableWidgetItem(", ".join(S.action_summary(a) for a in s["actions"]))
            h = hits.get(s["name"], 0)
            hit = QTableWidgetItem(str(h))
            hit.setTextAlignment(Qt.AlignCenter)
            if h:
                hit.setForeground(QBrush(QColor(theme.OK)))
            for c, item in enumerate((on, name, match, acts, hit)):
                self.table.setItem(r, c, item)

    def build_engine(self, dry_run: bool):
        from reforge.rules.engine import RuleEngine
        from reforge.rules.spec import build_rules

        return RuleEngine(build_rules(self.specs), dry_run=dry_run)
