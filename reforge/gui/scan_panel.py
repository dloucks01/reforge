"""Active scan tab — host/port/service discovery, feeding the recon inventory."""

from __future__ import annotations

import threading
from typing import Callable

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
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

from reforge.capture.registry import list_interfaces
from reforge.scan import discovery, tcp
from reforge.scan.engine import ScanEngine
from reforge.scan.targets import expand_targets, parse_ports

COLS = ["Host", "Port", "State", "Service / MAC"]


class ScanPanel(QWidget):
    def __init__(self, get_inventory: Callable | None = None, parent=None):
        super().__init__(parent)
        self._get_inv = get_inventory
        self._worker: threading.Thread | None = None
        self._rows: list[tuple] = []

        root = QVBoxLayout(self)
        row = QHBoxLayout()
        self.target = QLineEdit(); self.target.setPlaceholderText("target: 10.0.0.0/24, host, or 10.0.0.1-20")
        self.ports = QLineEdit("22,80,443,445,3389,8080")
        self.mode = QComboBox(); self.mode.addItems(["connect", "syn", "arp-discover"])
        self.iface = QComboBox(); self.iface.addItems(list_interfaces() or ["<none>"])
        self.banners = QCheckBox("banners"); self.banners.setChecked(True)
        self.run_btn = QPushButton("Scan"); self.run_btn.clicked.connect(self.run_scan)
        for w in (QLabel("Target:"), self.target, QLabel("Ports:"), self.ports,
                  QLabel("Mode:"), self.mode, QLabel("Iface:"), self.iface,
                  self.banners, self.run_btn):
            row.addWidget(w)
        root.addLayout(row)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        root.addWidget(self.table)

        self.status = QLabel("Enter a target and scan.")
        root.addWidget(self.status)

        self._poll = QTimer(self); self._poll.setInterval(300)
        self._poll.timeout.connect(self._check)

    def run_scan(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        try:
            targets = expand_targets(self.target.text().strip())
        except Exception as exc:
            self.status.setText(f"bad target: {exc}"); return
        if not targets:
            self.status.setText("no targets"); return
        mode = self.mode.currentText()
        ports = parse_ports(self.ports.text()) if mode != "arp-discover" else []
        iface = self.iface.currentText()
        banners = self.banners.isChecked()
        self._rows = []

        def work():
            try:
                if mode == "arp-discover":
                    alive = discovery.arp_sweep(targets, discovery.default_arp_prober(iface))
                    self._rows = [(ip, "", "up", mac) for ip, mac in alive.items()]
                else:
                    scanner = (tcp.ConnectScanner() if mode == "connect"
                               else tcp.SynScanner(tcp.default_prober()))
                    inv = self._get_inv() if self._get_inv else None
                    eng = ScanEngine(inv)
                    results = eng.scan_ports(targets, ports, scanner, banners=banners)
                    rows = []
                    for host, states in results.items():
                        for port, st in sorted(states.items()):
                            if st != "closed":
                                svc = eng.inv.hosts.get(host).services.get(port, "") if st == "open" else ""
                                rows.append((host, str(port), st, svc))
                    self._rows = rows
            except Exception as exc:
                self._rows = [("error", "", "", str(exc))]

        self._worker = threading.Thread(target=work, daemon=True)
        self._worker.start()
        self._poll.start()
        self.run_btn.setEnabled(False)
        self.status.setText(f"Scanning {len(targets)} host(s) [{mode}]…")

    def _check(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._poll.stop()
        self.run_btn.setEnabled(True)
        self.table.setRowCount(0)
        for host, port, state, svc in self._rows:
            r = self.table.rowCount(); self.table.insertRow(r)
            for c, v in enumerate((host, port, state, svc)):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.status.setText(f"Done — {len(self._rows)} result(s).")
