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
from reforge.attacks.stream_harvester import StreamHarvester
from reforge.gui import theme

COLS = ["Kind", "Proto", "From", "To", "Username", "Secret"]


class CredsPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.extractor = CredentialExtractor()   # per-packet (incl. non-TCP: SNMP)
        self.stream = StreamHarvester()          # multi-segment TCP reassembly
        self._seen: set = set()
        self.harvested: list = []

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

        creds = []
        try:
            creds += self.extractor.extract(Ether(data))   # non-TCP + single-segment
        except Exception:
            pass
        try:
            creds += self.stream.add_frame(data)            # multi-segment TCP
        except Exception:
            pass
        added = False
        for c in creds:
            key = (c.kind, c.username, c.secret, c.src, c.dst)
            if key in self._seen:
                continue
            self._seen.add(key)
            self.harvested.append(c.as_dict())
            self._add_row(c)
            added = True
        if added:
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
        self.harvested.clear()          # keep the report list in sync with the view
        self.extractor = CredentialExtractor()
        self.stream = StreamHarvester()
        self.count.setText("Credentials harvested: 0")

    def harvested_creds(self) -> list:
        return list(self.harvested)

    def load_creds(self, dicts) -> None:
        from types import SimpleNamespace
        for d in dicts:
            key = (d.get("kind"), d.get("username"), d.get("secret"), d.get("src"), d.get("dst"))
            if key in self._seen:
                continue
            self._seen.add(key)
            self.harvested.append(dict(d))
            self._add_row(SimpleNamespace(
                kind=d.get("kind", ""), proto=d.get("proto", ""),
                src=d.get("src", ""), dst=d.get("dst", ""),
                username=d.get("username", ""), secret=d.get("secret", "")))
        self.count.setText(f"Credentials harvested: {len(self._seen)}")
