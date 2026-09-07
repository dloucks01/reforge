"""Active MITM controls: ARP spoof, DNS spoof, name-service poisoning.

Each section constructs a module and starts/stops its runner (root required).
For authorized testing only.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from reforge.capture.registry import list_interfaces


def _ifaces():
    return list_interfaces() or ["<none>"]


class AttacksPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._arp = None
        self._dns = None
        self._name = None

        root = QVBoxLayout(self)
        note = QLabel("Active on-path attacks — authorized engagements only. Needs root.")
        note.setStyleSheet("color: palette(mid);")
        root.addWidget(note)
        root.addWidget(self._arp_box())
        root.addWidget(self._dns_box())
        root.addWidget(self._name_box())
        root.addStretch(1)

    # ---- ARP ----------------------------------------------------------------
    def _arp_box(self) -> QGroupBox:
        box = QGroupBox("ARP cache poisoning (become the gateway)")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.arp_if = QComboBox(); self.arp_if.addItems(_ifaces())
        self.arp_victim = QLineEdit(); self.arp_victim.setPlaceholderText("victim IP")
        self.arp_gw = QLineEdit(); self.arp_gw.setPlaceholderText("gateway IP")
        b_start = QPushButton("Start"); b_start.clicked.connect(self._arp_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._arp_stop)
        for w in (QLabel("Iface:"), self.arp_if, self.arp_victim, self.arp_gw, b_start, b_stop):
            row.addWidget(w)
        v.addLayout(row)
        self.arp_status = QLabel("idle"); v.addWidget(self.arp_status)
        return box

    def _arp_start(self):
        from reforge.attacks.arp_spoof import ArpSpoofer

        self._arp_stop()
        self._arp = ArpSpoofer(self.arp_if.currentText(), self.arp_victim.text().strip(),
                               self.arp_gw.text().strip())
        try:
            ok = self._arp.start()
            self.arp_status.setText("poisoning…" if ok else "failed to resolve MACs (root? live net?)")
        except Exception as exc:
            self.arp_status.setText(f"error: {exc}")

    def _arp_stop(self):
        if self._arp:
            try:
                self._arp.stop()
            except Exception:
                pass
            self._arp = None
            self.arp_status.setText("stopped (restored)")

    # ---- DNS ----------------------------------------------------------------
    def _dns_box(self) -> QGroupBox:
        box = QGroupBox("DNS spoofing (forge answers)")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.dns_if = QComboBox(); self.dns_if.addItems(_ifaces())
        b_start = QPushButton("Start"); b_start.clicked.connect(self._dns_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._dns_stop)
        for w in (QLabel("Iface:"), self.dns_if, b_start, b_stop):
            row.addWidget(w)
        row.addStretch(1)
        v.addLayout(row)
        self.dns_map = QPlainTextEdit()
        self.dns_map.setPlaceholderText("one mapping per line:  host=ip   (e.g. *.corp.local=10.0.0.66)")
        self.dns_map.setMaximumHeight(80)
        v.addWidget(self.dns_map)
        self.dns_status = QLabel("idle"); v.addWidget(self.dns_status)
        return box

    def _parse_map(self) -> dict:
        out = {}
        for line in self.dns_map.toPlainText().splitlines():
            if "=" in line:
                k, _, val = line.partition("=")
                out[k.strip().lower()] = val.strip()
        return out

    def _dns_start(self):
        from reforge.attacks.dns_spoof import DnsSpoofer

        self._dns_stop()
        hostmap = self._parse_map()
        if not hostmap:
            self.dns_status.setText("no mappings defined")
            return
        self._dns = DnsSpoofer(self.dns_if.currentText(), hostmap)
        try:
            self._dns.start()
            self.dns_status.setText(f"spoofing ({len(hostmap)} mappings)…")
        except Exception as exc:
            self.dns_status.setText(f"error: {exc}")

    def _dns_stop(self):
        if self._dns:
            try:
                self._dns.stop()
            except Exception:
                pass
            self._dns = None
            self.dns_status.setText("stopped")

    # ---- name poisoning -----------------------------------------------------
    def _name_box(self) -> QGroupBox:
        box = QGroupBox("Name poisoning (LLMNR / mDNS / NBT-NS)")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.name_if = QComboBox(); self.name_if.addItems(_ifaces())
        self.name_ip = QLineEdit(); self.name_ip.setPlaceholderText("our IP (redirect target)")
        b_start = QPushButton("Start"); b_start.clicked.connect(self._name_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._name_stop)
        for w in (QLabel("Iface:"), self.name_if, self.name_ip, b_start, b_stop):
            row.addWidget(w)
        v.addLayout(row)
        self.name_status = QLabel("idle"); v.addWidget(self.name_status)
        return box

    def _name_start(self):
        from reforge.attacks.namepoison import NamePoisoner

        self._name_stop()
        self._name = NamePoisoner(self.name_if.currentText(), self.name_ip.text().strip())
        try:
            self._name.start()
            self.name_status.setText("poisoning name queries…")
        except Exception as exc:
            self.name_status.setText(f"error: {exc}")

    def _name_stop(self):
        if self._name:
            try:
                self._name.stop()
            except Exception:
                pass
            self._name = None
            self.name_status.setText("stopped")

    def stop_all(self):
        self._arp_stop(); self._dns_stop(); self._name_stop()
