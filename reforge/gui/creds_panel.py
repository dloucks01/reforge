"""Harvested-credentials panel — live feed of secrets seen in captured traffic."""

from __future__ import annotations

from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.attacks.creds import CredentialExtractor
from reforge.gui import theme

COLS = ["Kind", "Proto", "From", "To", "Username", "Secret"]


class CredsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.extractor = CredentialExtractor()
        self._seen: set = set()

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        self.count = QLabel("Credentials harvested: 0")
        self.count.setStyleSheet("font-weight: 700;")
        clr = QPushButton("Clear"); clr.clicked.connect(self.clear)
        bar.addWidget(self.count); bar.addStretch(1); bar.addWidget(clr)
        root.addLayout(bar)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        root.addWidget(self.table)

    def add_from_frame(self, data: bytes) -> None:
        from scapy.layers.l2 import Ether

        try:
            creds = self.extractor.extract(Ether(data))
        except Exception:
            return
        for c in creds:
            key = (c.kind, c.username, c.secret, c.src, c.dst)
            if key in self._seen:
                continue
            self._seen.add(key)
            self._add_row(c)
        if creds:
            self.count.setText(f"Credentials harvested: {len(self._seen)}")

    def _add_row(self, c) -> None:
        r = self.table.rowCount()
        self.table.insertRow(r)
        vals = [c.kind, c.proto, c.src, c.dst, c.username, c.secret]
        for col, v in enumerate(vals):
            item = QTableWidgetItem(str(v))
            if col in (4, 5) and v:
                item.setForeground(QBrush(QColor(theme.OK)))
            self.table.setItem(r, col, item)

    def clear(self) -> None:
        self.table.setRowCount(0)
        self._seen.clear()
        self.extractor = CredentialExtractor()
        self.count.setText("Credentials harvested: 0")
