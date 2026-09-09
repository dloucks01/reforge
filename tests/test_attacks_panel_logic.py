"""AttacksPanel pure UI logic: victim selection, host population, status text.

The discover/start paths use threads + root; these cover the deterministic bits
that run headless."""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def _panel(app):
    from reforge.gui.attacks_panel import AttacksPanel
    return AttacksPanel()


def test_arp_populate_and_checked_victims(app):
    from PySide6.QtCore import Qt

    p = _panel(app)
    p._populate_hosts([("10.0.0.1", "aa:00:00:00:00:01"),
                       ("10.0.0.50", "aa:00:00:00:00:50"),
                       ("10.0.0.51", "aa:00:00:00:00:51")], gw="10.0.0.1")
    assert p.arp_gw.text() == "10.0.0.1"                    # gateway auto-filled
    assert p.arp_hosts.rowCount() == 3
    # check the two non-gateway hosts
    for r in range(p.arp_hosts.rowCount()):
        if p.arp_hosts.item(r, 0).data(Qt.UserRole) in ("10.0.0.50", "10.0.0.51"):
            p.arp_hosts.item(r, 0).setCheckState(Qt.Checked)
    assert sorted(p._arp_checked_victims()) == ["10.0.0.50", "10.0.0.51"]


def test_arp_checked_excludes_gateway(app):
    from PySide6.QtCore import Qt

    p = _panel(app)
    p._populate_hosts([("10.0.0.1", "aa:00:00:00:00:01")], gw="10.0.0.1")
    p.arp_hosts.item(0, 0).setCheckState(Qt.Checked)         # check the gateway
    assert p._arp_checked_victims() == []                    # gateway is never a victim


def test_arp_status_rendering(app):
    p = _panel(app)
    p._render_arp_status({"forwarding_on": True, "targets": ["10.0.0.50"],
                          "gateway": "10.0.0.1", "relayed": 12, "sent": 40,
                          "unresolved": []})
    assert "MITM ACTIVE" in p.arp_status.text() and "10.0.0.1" in p.arp_status.text()
    # forwarding off -> the DoS warning is shown
    p._render_arp_status({"forwarding_on": False, "targets": ["10.0.0.50"],
                          "gateway": "10.0.0.1", "relayed": 0, "sent": 5,
                          "unresolved": ["10.0.0.51"]})
    assert "OFF" in p.arp_status.text() and "10.0.0.51" in p.arp_status.text()


def test_ndp_populate_and_checked_victims(app):
    from PySide6.QtCore import Qt

    p = _panel(app)
    p._populate_ndp_hosts([("fd00::1", "aa:00:00:00:00:01"),
                           ("fd00::50", "aa:00:00:00:00:50")], router="fd00::1")
    assert p.ndp_router.text() == "fd00::1"
    for r in range(p.ndp_hosts.rowCount()):
        if p.ndp_hosts.item(r, 0).data(Qt.UserRole) == "fd00::50":
            p.ndp_hosts.item(r, 0).setCheckState(Qt.Checked)
    assert p._ndp_checked_victims() == ["fd00::50"]


def test_ndp_status_rendering(app):
    p = _panel(app)
    p._render_ndp_status({"forwarding_on": True, "targets": ["fd00::50"],
                          "router": "fd00::1", "relayed": 3, "sent": 20,
                          "unresolved": []})
    assert "NDP MITM ACTIVE" in p.ndp_status.text()


def test_activity_formatters_distinguish_dead_from_working(app):
    from reforge.gui.attacks_panel import AttacksPanel as P
    # DNS: not on-path / seeing-not-matching / working
    assert P._fmt_dns({"seen": 0, "answered": 0, "mappings": 2})[1] is False
    t, live = P._fmt_dns({"seen": 5, "answered": 0, "mappings": 2})
    assert live is False and "0 matched" in t
    assert P._fmt_dns({"seen": 5, "answered": 3, "mappings": 2})[1] is True
    # name poisoning
    assert P._fmt_name({"seen": 0, "poisoned": 0})[1] is False
    assert P._fmt_name({"seen": 4, "poisoned": 2})[1] is True
    # rogue dhcp
    assert P._fmt_dhcp({"discovers": 0, "offered": 0, "requests": 0, "leased": 0})[1] is False
    t, live = P._fmt_dhcp({"discovers": 2, "offered": 2, "requests": 1, "leased": 1})
    assert live is True and "leased 1" in t


def test_poll_activity_updates_status_from_a_runner(app):
    p = _panel(app)

    class FakeDns:
        def status(self):
            return {"seen": 7, "answered": 4, "mappings": 1}

    p._dns = FakeDns()
    p._poll_activity()                       # must not raise; updates the label
    assert "seen 7" in p.dns_status.text() and "answered 4" in p.dns_status.text()


def test_engine_note_guides_nfqueue_choice():
    from reforge.gui.attacks_panel import AttacksPanel
    # nfqueue ready -> names the routed-hop trade-off and the bridge alternative
    note = AttacksPanel._engine_note(iface_count=1, nfqueue_ok=True)
    assert "NFQUEUE" in note and "L3 hop" in note and "Bridge" in note
    # nfqueue stack missing -> a warning, not a green light
    note = AttacksPanel._engine_note(iface_count=1, nfqueue_ok=False)
    assert note.startswith("⚠")
