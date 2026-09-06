"""Interactive intercept & edit panel.

Lists packets the engine HELD, lets the operator edit fields (editable tree) or
raw bytes (hex box), then Forward / Forward-modified / Drop. Resolving calls back
into the InterceptQueue, which releases the packet on the correct egress.
"""

from __future__ import annotations

import time

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from reforge.core.packet import Packet
from reforge.dissect import scapy_tree

HELD_COLUMNS = ["ID", "Ingress", "Proto", "Info", "Age"]
_LAYER_FIELD = Qt.UserRole + 1


class InterceptPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.queue = None
        self._current_id: int | None = None
        self._work: bytes = b""
        self._applying = False

        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)

        self.header = QLabel("Interception queue — held: 0")
        self.header.setStyleSheet("font-weight: 700;")
        root.addWidget(self.header)

        split = QSplitter(Qt.Vertical)

        self.table = QTableWidget(0, len(HELD_COLUMNS))
        self.table.setHorizontalHeaderLabels(HELD_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_select)
        split.addWidget(self.table)

        editor = QWidget()
        elayout = QVBoxLayout(editor)
        elayout.setContentsMargins(0, 0, 0, 0)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value (double-click to edit)"])
        self.tree.setColumnWidth(0, 220)
        self.tree.itemChanged.connect(self._on_field_edited)
        elayout.addWidget(self.tree)

        mono = QFont("JetBrains Mono"); mono.setStyleHint(QFont.Monospace)
        self.hex_edit = QPlainTextEdit()
        self.hex_edit.setFont(mono)
        self.hex_edit.setPlaceholderText("raw bytes as hex (editable) — then Apply hex")
        elayout.addWidget(self.hex_edit)

        buttons = QHBoxLayout()
        self.btn_apply_hex = QPushButton("Apply hex")
        self.btn_fwd = QPushButton("Forward")
        self.btn_mod = QPushButton("Forward modified")
        self.btn_drop = QPushButton("Drop")
        self.btn_apply_hex.clicked.connect(self._apply_hex)
        self.btn_fwd.clicked.connect(lambda: self._resolve("forward"))
        self.btn_mod.clicked.connect(lambda: self._resolve("modify"))
        self.btn_drop.clicked.connect(lambda: self._resolve("drop"))
        buttons.addWidget(self.btn_apply_hex)
        buttons.addStretch(1)
        buttons.addWidget(self.btn_fwd)
        buttons.addWidget(self.btn_mod)
        buttons.addWidget(self.btn_drop)
        elayout.addLayout(buttons)

        split.addWidget(editor)
        split.setSizes([180, 360])
        root.addWidget(split)
        self._set_buttons_enabled(False)

    # ---- queue binding ------------------------------------------------------
    def set_queue(self, queue) -> None:
        self.queue = queue
        self._current_id = None
        if queue is None:
            self.table.setRowCount(0)
            self.tree.clear()
            self.hex_edit.clear()
            self.header.setText("Interception queue — held: 0")
            self._set_buttons_enabled(False)
            return
        self.refresh_pending()

    def refresh_pending(self) -> None:
        if self.queue is None:
            return
        pending = self.queue.pending()
        self.header.setText(f"Interception queue — held: {len(pending)}")
        selected = self._current_id
        self.table.setRowCount(0)
        now = time.time()
        for hp in pending:
            r = self.table.rowCount()
            self.table.insertRow(r)
            try:
                pkt = __import__("scapy.layers.l2", fromlist=["Ether"]).Ether(hp.data)
                row = scapy_tree.summarize(pkt)
                proto, info = row.proto, row.info
            except Exception:
                proto, info = "?", ""
            vals = [str(hp.id), hp.ingress, proto, info, f"{now - hp.ts:.1f}s"]
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                item.setData(Qt.UserRole, hp.id)
                self.table.setItem(r, c, item)
        # keep the previously selected row if still present
        if selected is not None:
            for r in range(self.table.rowCount()):
                if self.table.item(r, 0).data(Qt.UserRole) == selected:
                    self.table.selectRow(r)
                    break

    # ---- detail / editing ---------------------------------------------------
    def _on_select(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows or self.queue is None:
            return
        pid = self.table.item(rows[0].row(), 0).data(Qt.UserRole)
        hp = self.queue.get(pid)
        if hp is None:
            return
        self._current_id = pid
        self._set_work_bytes(hp.data)
        self._set_buttons_enabled(True)

    def _set_work_bytes(self, data: bytes) -> None:
        self._work = bytes(data)
        self._rebuild_tree()
        self._applying = True
        self.hex_edit.setPlainText(" ".join(f"{b:02x}" for b in self._work))
        self._applying = False

    def _rebuild_tree(self) -> None:
        self._applying = True
        self.tree.clear()
        try:
            from scapy.layers.l2 import Ether

            for layer in scapy_tree.to_tree(Ether(self._work)):
                parent = QTreeWidgetItem([layer.name, ""])
                parent.setFlags(parent.flags() & ~Qt.ItemIsEditable)
                for f in layer.fields:
                    child = QTreeWidgetItem([f.name, f.human])
                    child.setFlags(child.flags() | Qt.ItemIsEditable)
                    child.setData(0, _LAYER_FIELD, (layer.name, f.name))
                    parent.addChild(child)
                self.tree.addTopLevelItem(parent)
                parent.setExpanded(True)
        except Exception:
            pass
        self._applying = False

    def _on_field_edited(self, item: QTreeWidgetItem, column: int) -> None:
        if self._applying or column != 1:
            return
        meta = item.data(0, _LAYER_FIELD)
        if not meta:
            return
        layer, field = meta
        text = item.text(1)
        try:
            pkt = Packet.from_bytes(self._work, link="ether")
            pkt.set_field(layer, field, text)
            self._set_work_bytes(pkt.rebuild())
        except Exception:
            self._rebuild_tree()  # revert display on bad input

    def _apply_hex(self) -> None:
        raw = self.hex_edit.toPlainText().replace(":", " ").split()
        try:
            data = bytes(int(b, 16) for b in raw)
            self._set_work_bytes(data)
        except Exception:
            pass

    def _resolve(self, action: str) -> None:
        if self.queue is None or self._current_id is None:
            return
        self.queue.resolve(self._current_id, action, self._work if action == "modify" else None)
        self._current_id = None
        self.tree.clear()
        self.hex_edit.clear()
        self._set_buttons_enabled(False)
        self.refresh_pending()

    def _set_buttons_enabled(self, on: bool) -> None:
        for b in (self.btn_apply_hex, self.btn_fwd, self.btn_mod, self.btn_drop):
            b.setEnabled(on)
