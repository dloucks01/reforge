"""Visual packet builder + transmitter (Phase 5).

Stack layers from a palette, edit every field, preview the built bytes, and send
one-shot / looped / send-and-receive. Load a captured packet to edit-and-resend,
and save/load templates.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.capture.registry import list_interfaces
from reforge.craft import builder, sender
from reforge.dissect import scapy_tree


def _L(layer: str, **fields) -> dict:
    return {"layer": layer, "fields": {k: str(v) for k, v in fields.items()}}


# common starting points: (name, {"layers": [...]})
_TEMPLATES = [
    ("TCP SYN", {"layers": [_L("Ether"), _L("IP", dst="10.0.0.1"),
                            _L("TCP", dport=80, flags="S")]}),
    ("HTTP GET", {"layers": [_L("Ether"), _L("IP", dst="10.0.0.1"),
                             _L("TCP", dport=80, flags="PA"),
                             _L("Raw", load="GET / HTTP/1.1\r\nHost: target\r\n\r\n")]}),
    ("ICMP echo", {"layers": [_L("Ether"), _L("IP", dst="10.0.0.1"), _L("ICMP", type=8)]}),
    ("UDP datagram", {"layers": [_L("Ether"), _L("IP", dst="10.0.0.1"), _L("UDP", dport=53)]}),
    ("DNS query", {"layers": [_L("Ether"), _L("IP", dst="8.8.8.8"),
                              _L("UDP", dport=53), _L("DNS", rd=1)]}),
    ("ARP request", {"layers": [_L("Ether", dst="ff:ff:ff:ff:ff:ff"),
                                _L("ARP", op=1, pdst="10.0.0.1")]}),
    ("VLAN + TCP", {"layers": [_L("Ether"), _L("Dot1Q", vlan=100),
                               _L("IP", dst="10.0.0.1"), _L("TCP", dport=80, flags="S")]}),
]


class BuilderPanel(QWidget):
    def __init__(self, get_selected_packet: Callable[[], bytes | None] | None = None, parent=None):
        super().__init__(parent)
        self._get_selected = get_selected_packet
        self.layers: list[dict] = []
        self._loading = False

        root = QVBoxLayout(self)

        # --- palette row ---
        palette = QHBoxLayout()
        self.layer_combo = QComboBox()
        self.layer_combo.addItems(builder.available_layers())
        add = QPushButton("Add layer"); add.clicked.connect(self._add_layer)
        rm = QPushButton("Remove"); rm.clicked.connect(self._remove_layer)
        up = QPushButton("↑"); up.clicked.connect(lambda: self._move(-1))
        dn = QPushButton("↓"); dn.clicked.connect(lambda: self._move(1))
        from_cap = QPushButton("Load from capture"); from_cap.clicked.connect(self._load_from_capture)
        clr = QPushButton("Clear"); clr.clicked.connect(self._clear)
        self.template_combo = QComboBox(); self.template_combo.addItem("Templates…")
        for name, _spec in _TEMPLATES:
            self.template_combo.addItem(name)
        self.template_combo.setToolTip("Start from a common packet template")
        self.template_combo.activated.connect(self._apply_template)
        for w in (QLabel("Layer:"), self.layer_combo, add, rm, up, dn):
            palette.addWidget(w)
        palette.addStretch(1)
        palette.addWidget(self.template_combo)
        palette.addWidget(from_cap); palette.addWidget(clr)
        root.addLayout(palette)

        # --- middle: layer list | field editor | preview ---
        mid = QSplitter(Qt.Horizontal)

        self.stack = QListWidget()
        self.stack.currentRowChanged.connect(self._on_layer_selected)
        mid.addWidget(self.stack)

        self.fields = QTableWidget(0, 2)
        self.fields.setHorizontalHeaderLabels(["Field", "Value"])
        self.fields.horizontalHeader().setStretchLastSection(True)
        self.fields.cellChanged.connect(self._on_field_changed)
        mid.addWidget(self.fields)

        mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace)
        self.preview = QPlainTextEdit(); self.preview.setReadOnly(True); self.preview.setFont(mono)
        mid.addWidget(self.preview)
        mid.setSizes([220, 380, 460])
        root.addWidget(mid, 1)

        # --- send controls ---
        send = QHBoxLayout()
        self.iface = QComboBox(); self.iface.addItems(list_interfaces() or ["<none>"])
        self.count = QSpinBox(); self.count.setRange(1, 1000000); self.count.setValue(1)
        self.interval = QLineEdit("0.0"); self.interval.setMaximumWidth(70)
        self.l2 = QCheckBox("L2"); self.l2.setChecked(True)
        btn_send = QPushButton("Send"); btn_send.clicked.connect(self._send)
        btn_sr = QPushButton("Send && Receive"); btn_sr.clicked.connect(self._send_receive)
        btn_fuzz = QPushButton("Fuzz send"); btn_fuzz.clicked.connect(self._fuzz_send)
        from reforge.evasion.techniques import TECHNIQUES
        self.evade_combo = QComboBox(); self.evade_combo.addItems(list(TECHNIQUES))
        btn_evade = QPushButton("Evade send"); btn_evade.clicked.connect(self._evade_send)
        proto = QPushButton("Load protocol"); proto.clicked.connect(self._load_protocol)
        save = QPushButton("Save template"); save.clicked.connect(self._save)
        load = QPushButton("Load template"); load.clicked.connect(self._load)
        for w in (QLabel("Iface:"), self.iface, QLabel("Count:"), self.count,
                  QLabel("Interval:"), self.interval, self.l2, btn_send, btn_sr, btn_fuzz,
                  self.evade_combo, btn_evade):
            send.addWidget(w)
        send.addStretch(1)
        send.addWidget(proto); send.addWidget(save); send.addWidget(load)
        root.addLayout(send)

        self.status = QLabel("Add a layer to begin.")
        self.status.setStyleSheet("color: palette(mid);")
        root.addWidget(self.status)

    # ---- layer stack --------------------------------------------------------
    def _add_layer(self) -> None:
        self.layers.append({"layer": self.layer_combo.currentText(), "fields": {}})
        self._refresh_stack(select=len(self.layers) - 1)

    def _remove_layer(self) -> None:
        i = self.stack.currentRow()
        if 0 <= i < len(self.layers):
            del self.layers[i]
            self._refresh_stack(select=min(i, len(self.layers) - 1))

    def _move(self, delta: int) -> None:
        i = self.stack.currentRow()
        j = i + delta
        if 0 <= i < len(self.layers) and 0 <= j < len(self.layers):
            self.layers[i], self.layers[j] = self.layers[j], self.layers[i]
            self._refresh_stack(select=j)

    def _clear(self) -> None:
        self.layers = []
        self._refresh_stack()

    def _refresh_stack(self, select: int = -1) -> None:
        self.stack.blockSignals(True)
        self.stack.clear()
        for ld in self.layers:
            extra = f"  ({len(ld['fields'])} set)" if ld["fields"] else ""
            self.stack.addItem(ld["layer"] + extra)
        self.stack.blockSignals(False)
        if 0 <= select < len(self.layers):
            self.stack.setCurrentRow(select)
        else:
            self._show_fields(-1)
        self._update_preview()

    # ---- field editor -------------------------------------------------------
    def _on_layer_selected(self, row: int) -> None:
        self._show_fields(row)

    def _show_fields(self, row: int) -> None:
        self._loading = True
        self.fields.setRowCount(0)
        if 0 <= row < len(self.layers):
            ld = self.layers[row]
            overrides = ld["fields"]
            for name, default in builder.layer_fields(ld["layer"]):
                r = self.fields.rowCount()
                self.fields.insertRow(r)
                key = QTableWidgetItem(name)
                key.setFlags(key.flags() & ~Qt.ItemIsEditable)
                val = QTableWidgetItem(str(overrides.get(name, default)))
                self.fields.setItem(r, 0, key)
                self.fields.setItem(r, 1, val)
        self._loading = False

    def _on_field_changed(self, row: int, col: int) -> None:
        if self._loading or col != 1:
            return
        i = self.stack.currentRow()
        if not (0 <= i < len(self.layers)):
            return
        field = self.fields.item(row, 0).text()
        self.layers[i]["fields"][field] = self.fields.item(row, 1).text()
        self._update_preview()

    # ---- preview / send -----------------------------------------------------
    def _current_bytes(self) -> bytes | None:
        try:
            return builder.spec_to_bytes({"layers": self.layers})
        except Exception as exc:
            self.status.setText(f"Build error: {exc}")
            return None

    def _update_preview(self) -> None:
        if not self.layers:
            self.preview.setPlainText("")
            self.status.setText("Add a layer to begin.")
            return
        data = self._current_bytes()
        if data is None:
            return
        try:
            from scapy.layers.l2 import Ether

            summary = Ether(data).summary()
        except Exception:
            summary = "(unparaseable)"
        hexdump = "\n".join(scapy_tree.hexdump_lines(data))
        self.preview.setPlainText(f"{summary}\n\n{hexdump}")
        self.status.setText(f"Built {len(data)} bytes.")

    def _send(self) -> None:
        data = self._current_bytes()
        if data is None:
            return
        iface = self.iface.currentText()
        try:
            interval = float(self.interval.text() or 0)
            n = sender.inject(iface, data, self.count.value(), interval, self.l2.isChecked())
            self.status.setText(f"Sent {n} packet(s) on {iface}.")
        except Exception as exc:
            QMessageBox.critical(self, "Send error", str(exc))

    def _send_receive(self) -> None:
        data = self._current_bytes()
        if data is None:
            return
        iface = self.iface.currentText()
        try:
            reply = sender.send_receive(iface, data, timeout=2.0, l2=self.l2.isChecked())
        except Exception as exc:
            QMessageBox.critical(self, "Send error", str(exc))
            return
        if reply is None:
            self.status.setText("Sent; no reply.")
            return
        from scapy.layers.l2 import Ether

        self.preview.setPlainText("REPLY: " + Ether(reply).summary() + "\n\n"
                                  + "\n".join(scapy_tree.hexdump_lines(reply)))
        self.status.setText(f"Reply: {len(reply)} bytes.")

    def _fuzz_send(self) -> None:
        data = self._current_bytes()
        if data is None:
            return
        from reforge.craft.fuzz import mutate

        iface = self.iface.currentText()
        try:
            for _ in range(self.count.value()):
                sender.inject(iface, mutate(data, mutations=3), 1, 0.0, self.l2.isChecked())
            self.status.setText(f"Fuzz-sent {self.count.value()} mutated variant(s) on {iface}.")
        except Exception as exc:
            QMessageBox.critical(self, "Send error", str(exc))

    def _evade_send(self) -> None:
        data = self._current_bytes()
        if data is None:
            return
        from scapy.layers.l2 import Ether

        from reforge.evasion.techniques import apply_evasion

        technique = self.evade_combo.currentText()
        iface = self.iface.currentText()
        try:
            frames = apply_evasion(Ether(data), technique)
            for f in frames:
                sender.inject(iface, f, 1, 0.0, self.l2.isChecked())
            self.status.setText(f"Sent {len(frames)} frame(s) via '{technique}' on {iface}.")
        except Exception as exc:
            QMessageBox.critical(self, "Evasion error", str(exc))

    def _load_protocol(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load protocol (JSON)", "", "JSON (*.json)")
        if not path:
            return
        from reforge.craft.custom_proto import define_protocol

        try:
            spec = json.loads(Path(path).read_text())
            define_protocol(spec)
        except Exception as exc:
            QMessageBox.critical(self, "Protocol error", str(exc))
            return
        self.layer_combo.clear()
        self.layer_combo.addItems(builder.available_layers())
        self.status.setText(f"Loaded protocol '{spec.get('name')}' — now in the layer palette.")

    # ---- templates / capture ------------------------------------------------
    def load_spec(self, spec: dict) -> None:
        self.layers = list(spec.get("layers", []))
        self._refresh_stack(select=0)

    def _apply_template(self, index: int) -> None:
        if index <= 0:
            return
        import copy

        self.load_spec(copy.deepcopy(_TEMPLATES[index - 1][1]))
        self.template_combo.setCurrentIndex(0)      # behave like a menu
        self.status.setText(f"Loaded template: {_TEMPLATES[index - 1][0]} — edit and send.")

    def _load_from_capture(self) -> None:
        if self._get_selected is None:
            return
        data = self._get_selected()
        if not data:
            self.status.setText("Select a packet in the Capture tab first.")
            return
        self.load_spec(builder.bytes_to_spec(data))
        self.status.setText("Loaded selected packet — edit and resend.")

    def _save(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save template", "packet.json", "JSON (*.json)")
        if path:
            _write_json(path, {"layers": self.layers})
            self.status.setText(f"Saved template -> {path}")

    def _load(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load template", "", "JSON (*.json)")
        if path:
            self.load_spec(json.loads(Path(path).read_text()))
            self.status.setText(f"Loaded template <- {path}")


def _write_json(path: str, obj: dict) -> None:
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
