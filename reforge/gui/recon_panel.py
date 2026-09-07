"""Recon panel — live asset inventory from observed traffic."""

from __future__ import annotations

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

from reforge.recon.assets import AssetInventory

COLS = ["IP", "MAC", "OS", "Services", "Hostnames"]


class ReconPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.inv = AssetInventory()
        self._dirty = False

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        bar = QHBoxLayout()
        self.count = QLabel("Hosts discovered: 0")
        self.count.setStyleSheet("font-weight: 700;")
        clr = QPushButton("Clear"); clr.clicked.connect(self.clear)
        bar.addWidget(self.count); bar.addStretch(1); bar.addWidget(clr)
        root.addLayout(bar)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        root.addWidget(self.table)

    def add_from_frame(self, data: bytes) -> None:
        from scapy.layers.l2 import Ether

        try:
            self.inv.observe(Ether(data))
            self._dirty = True
        except Exception:
            pass

    def refresh(self) -> None:
        if not self._dirty:
            return
        self._dirty = False
        hosts = self.inv.list_hosts()
        self.count.setText(f"Hosts discovered: {len(hosts)}")
        self.table.setRowCount(0)
        for h in hosts:
            r = self.table.rowCount()
            self.table.insertRow(r)
            services = ", ".join(f"{p}:{v}" for p, v in sorted(h.services.items()))
            os_txt = f"{h.os_family} ({h.os_confidence})" if h.os_family else ""
            vals = [h.ip, h.mac, os_txt, services, ", ".join(sorted(h.hostnames))]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))

    def clear(self) -> None:
        self.inv = AssetInventory()
        self.table.setRowCount(0)
        self.count.setText("Hosts discovered: 0")
