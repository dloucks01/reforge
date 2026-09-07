"""Distributed console — run a collector, watch merged sensor reports live."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.gui.errors import explain

HOST_COLS = ["IP", "MAC", "OS", "Services"]
CRED_COLS = ["Kind", "Proto", "From", "To", "User", "Secret"]


class ConsolePanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._collector = None
        self._server = None
        self._mtls = None            # (server_ctx, client_ctx, ca)

        root = QVBoxLayout(self)
        bar = QHBoxLayout()
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(9900)
        self.mtls = QCheckBox("mTLS"); self.mtls.setChecked(True)
        b_start = QPushButton("Start collector"); b_start.clicked.connect(self.start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self.stop)
        b_bundle = QPushButton("Export sensor bundle…"); b_bundle.clicked.connect(self.export_bundle)
        for w in (QLabel("Listen port:"), self.port, self.mtls, b_start, b_stop, b_bundle):
            bar.addWidget(w)
        bar.addStretch(1)
        root.addLayout(bar)

        self.summary = QLabel("Collector idle.")
        self.summary.setStyleSheet("font-weight: 700;")
        root.addWidget(self.summary)

        split = QSplitter(Qt.Vertical)
        self.hosts = QTableWidget(0, len(HOST_COLS))
        self.hosts.setHorizontalHeaderLabels(HOST_COLS)
        self.hosts.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.hosts.verticalHeader().setVisible(False)
        split.addWidget(self.hosts)
        self.creds = QTableWidget(0, len(CRED_COLS))
        self.creds.setHorizontalHeaderLabels(CRED_COLS)
        self.creds.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.creds.verticalHeader().setVisible(False)
        split.addWidget(self.creds)
        root.addWidget(split, 1)

        self._poll = QTimer(self); self._poll.setInterval(1000)
        self._poll.timeout.connect(self.refresh)

    def start(self):
        from reforge.distributed.collector import Collector
        from reforge.distributed.network import CollectorServer

        self.stop()
        server_ctx = None
        if self.mtls.isChecked():
            from reforge.distributed.tls import dev_mtls

            self._mtls = dev_mtls()
            server_ctx = self._mtls[0]
        self._collector = Collector()
        try:
            self._server = CollectorServer(self._collector, bind=("0.0.0.0", self.port.value()),
                                           ssl_context=server_ctx)
            port = self._server.start()
        except Exception as exc:
            self.summary.setText(f"error: {explain(exc)}"); return
        self._poll.start()
        mode = "mTLS" if server_ctx else "PLAINTEXT (bind loopback or tunnel!)"
        self.summary.setText(f"Collector on :{port} [{mode}] — waiting for sensors")

    def stop(self):
        self._poll.stop()
        if self._server:
            try:
                self._server.stop()
            except Exception:
                pass
            self._server = None
        if self._collector is not None:
            self.summary.setText("Collector stopped.")

    def refresh(self):
        if self._collector is None:
            return
        rep = self._collector.report()
        self.summary.setText(
            f"sensors: {len(self._collector.sensors)}   hosts: {len(rep.hosts)}   "
            f"creds: {len(rep.credentials)}   events: {len(rep.events)}")
        self.hosts.setRowCount(0)
        for h in rep.hosts:
            r = self.hosts.rowCount(); self.hosts.insertRow(r)
            svcs = ", ".join(f"{p}:{v}" for p, v in sorted(h.get("services", {}).items()))
            for c, v in enumerate((h.get("ip"), h.get("mac"), h.get("os_family"), svcs)):
                self.hosts.setItem(r, c, QTableWidgetItem(str(v)))
        self.creds.setRowCount(0)
        for cr in rep.credentials:
            r = self.creds.rowCount(); self.creds.insertRow(r)
            vals = (cr.get("kind"), cr.get("proto"), cr.get("src"), cr.get("dst"),
                    cr.get("username"), cr.get("secret"))
            for c, v in enumerate(vals):
                self.creds.setItem(r, c, QTableWidgetItem(str(v)))

    def export_bundle(self):
        directory = QFileDialog.getExistingDirectory(self, "Export sensor mTLS bundle to…")
        if not directory:
            return
        from pathlib import Path


        if self._mtls is None:
            from reforge.distributed.tls import dev_mtls
            self._mtls = dev_mtls()
        _sctx, _cctx, ca = self._mtls
        d = Path(directory)
        (d / "ca.pem").write_bytes(ca.ca_pem())
        for name in ("collector", "sensor"):
            cert, key = ca.cert_for(name)
            (d / f"{name}.crt").write_bytes(cert)
            (d / f"{name}.key").write_bytes(key)
        self.summary.setText(f"mTLS bundle exported to {directory} — deploy ca.pem + sensor.* "
                             f"to sensors, keep collector.* on the console")
