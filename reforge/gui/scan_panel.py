"""Active scan tab — host/port/service discovery, feeding the recon inventory."""

from __future__ import annotations

import threading
from collections.abc import Callable

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
from reforge.gui.errors import explain
from reforge.scan import discovery, tcp
from reforge.scan.engine import ScanEngine
from reforge.scan.targets import expand_targets, parse_ports

COLS = ["Host", "Port", "State", "Service / MAC"]

# common port sets: (label, ports expression)
_PORT_SETS = [
    ("Top 20", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080"),
    ("Web", "80,443,8080,8443,8000,8888"),
    ("Windows/AD", "88,135,139,389,445,464,636,3389,5985,5986"),
    ("Databases", "1433,1521,3306,5432,6379,9200,11211,27017"),
    ("Remote/mgmt", "22,23,3389,5900,5985,161,623"),
    ("System 1-1024", "1-1024"),
    ("All 1-65535", "1-65535"),
]


class ScanPanel(QWidget):
    def __init__(self, get_inventory: Callable | None = None, parent=None):
        super().__init__(parent)
        self._get_inv = get_inventory
        self.on_scan_done = None
        self._worker: threading.Thread | None = None
        self._rows: list[tuple] = []

        root = QVBoxLayout(self)
        row = QHBoxLayout()
        self.target = QLineEdit(); self.target.setPlaceholderText("target: 10.0.0.0/24, host, or 10.0.0.1-20")
        self.ports = QLineEdit("22,80,443,445,3389,8080")
        self.port_preset = QComboBox(); self.port_preset.addItem("Ports…")
        for label, _spec in _PORT_SETS:
            self.port_preset.addItem(label)
        self.port_preset.setToolTip("Fill the ports box with a common set")
        self.port_preset.activated.connect(self._apply_port_preset)
        self.mode = QComboBox(); self.mode.addItems(["connect", "syn", "arp-discover"])
        self.iface = QComboBox(); self.iface.addItems(list_interfaces() or ["<none>"])
        self.banners = QCheckBox("banners"); self.banners.setChecked(True)
        self.run_btn = QPushButton("Scan"); self.run_btn.clicked.connect(self.run_scan)
        for w in (QLabel("Target:"), self.target, QLabel("Ports:"), self.ports,
                  self.port_preset, QLabel("Mode:"), self.mode, QLabel("Iface:"), self.iface,
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

    def _apply_port_preset(self, index: int) -> None:
        if index <= 0:
            return
        self.ports.setText(_PORT_SETS[index - 1][1])
        self.port_preset.setCurrentIndex(0)         # behave like a menu

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
                self._rows = [("error", "", "", explain(exc))]

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
        if self.on_scan_done is not None:
            self.on_scan_done(f"{self.target.text().strip()} -> {len(self._rows)} result(s)")
