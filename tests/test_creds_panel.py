"""CredsPanel: harvest from frames, load/save, and clear."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def test_add_from_frame_populates_table(app):
    from reforge.gui.creds_panel import CredsPanel
    from reforge.testlab import traffic as T

    panel = CredsPanel()
    for _ts, fb in T.http_login(user="admin", password="s3cr3t"):
        panel.add_from_frame(fb)
    assert panel.table.rowCount() >= 1
    users = {panel.table.item(r, 4).text() for r in range(panel.table.rowCount())}
    assert "admin" in users
    assert panel.harvested_creds()                      # dict list for the report


def test_load_creds_and_clear(app):
    from reforge.gui.creds_panel import CredsPanel
    panel = CredsPanel()
    panel.load_creds([{"kind": "ftp", "proto": "FTP", "src": "10.0.0.5",
                       "dst": "10.0.0.6", "username": "bob", "secret": "pw",
                       "detail": "USER/PASS"}])
    assert panel.table.rowCount() == 1
    panel.clear()
    assert panel.table.rowCount() == 0 and panel.harvested_creds() == []
