"""Low-priority review findings: SNI filename, HTTP buffer cap, helper peer
auth, console loopback bind, counter accuracy (2026-09 review §3.10-§3.17)."""

from __future__ import annotations

import os
import struct

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


# --- §3.16: SNI-derived cert filename is sanitized + unique ------------------
def test_safe_name_strips_path_separators():
    from reforge.attacks.tls_ca import _safe_name
    n = _safe_name("../../etc/cron.d/evil")
    assert "/" not in n and "\\" not in n          # no path separators -> can't escape
    # distinct hosts don't collide even after sanitizing
    assert _safe_name("a/b") != _safe_name("a_b")
    assert _safe_name("example.com").startswith("example.com-")


def test_context_for_writes_inside_tmp(tmp_path):
    from reforge.attacks.tls_ca import DynamicCA
    ca = DynamicCA()
    try:
        ca.context_for("../../../etc/whatever")     # crafted SNI
        # every file the CA wrote stays within its temp dir
        for p in ca._tmp.iterdir():
            assert p.parent == ca._tmp
    finally:
        ca.close()


# --- §3.13: HTTP framer caps an unterminated message ------------------------
def test_httpframer_caps_unbounded_response():
    from reforge.core.httpframer import HttpFramer
    fr = HttpFramer(max_buffer=1024)
    # a response with no Content-Length/chunked: normally buffers until close
    out = fr.feed(b"HTTP/1.1 200 OK\r\n\r\n")
    assert out == []                                 # incomplete, still buffering
    big = fr.feed(b"A" * 2000)                        # push past the cap
    assert big and len(big[0]) >= 1024               # emitted instead of growing forever
    assert len(fr.buf) == 0


def test_httpframer_caps_headers_without_terminator():
    from reforge.core.httpframer import HttpFramer
    fr = HttpFramer(max_buffer=512)
    assert fr.feed(b"GET / HTTP/1.1\r\nX: ") == []   # no blank line yet
    out = fr.feed(b"z" * 1000)                        # header block never terminates
    assert out and len(fr.buf) == 0                   # capped, didn't grow unbounded


# --- §3.17: helper rejects an unauthorized peer -----------------------------
class _FakeConn:
    def __init__(self, uid):
        self._uid = uid

    def getsockopt(self, level, opt, size):
        return struct.pack("3i", 1234, self._uid, self._uid)


def test_peer_authorized_accepts_root_and_self():
    from reforge.privhelper.helper import _peer_authorized
    assert _peer_authorized(_FakeConn(0)) is True            # root
    assert _peer_authorized(_FakeConn(os.geteuid())) is True  # the helper's own uid


def test_peer_authorized_rejects_other_uid():
    from reforge.privhelper.helper import _peer_authorized
    other = os.geteuid() + 4242
    assert _peer_authorized(_FakeConn(other)) is False


def test_peer_authorized_fails_closed_on_error():
    from reforge.privhelper.helper import _peer_authorized

    class _Bad:
        def getsockopt(self, *a):
            raise OSError("no peercred")

    assert _peer_authorized(_Bad()) is False


# --- §3.10: console collector binds loopback when mTLS is off ---------------
@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication
    yield QApplication.instance() or QApplication([])


def test_console_binds_loopback_without_mtls(app, monkeypatch):
    from reforge.gui.console_panel import ConsolePanel
    binds = {}

    class _FakeServer:
        def __init__(self, collector, bind, ssl_context=None):
            binds["host"], binds["ctx"] = bind[0], ssl_context

        def start(self):
            return 9999

        def stop(self):
            pass

    monkeypatch.setattr("reforge.distributed.network.CollectorServer", _FakeServer)
    p = ConsolePanel()
    p.mtls.setChecked(False)
    p.start()
    assert binds["host"] == "127.0.0.1" and binds["ctx"] is None
    p.stop()


# --- §2.6: RA flooding (distinct rogue RAs) + steps wired --------------------
def test_ra_flood_builds_distinct_routers():
    import random as _r

    from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo
    from reforge.attacks.ndp import ra_flood_packets

    pkts = ra_flood_packets(20, _r.Random(1))
    assert len(pkts) == 20
    assert all(p.haslayer(ICMPv6ND_RA) for p in pkts)              # real RAs
    prefixes = {p[ICMPv6NDOptPrefixInfo].prefix for p in pkts}
    macs = {p.src for p in pkts}
    assert len(prefixes) > 1 and len(macs) > 1                     # varied -> a flood
    # deterministic for a given seed
    again = ra_flood_packets(20, _r.Random(1))
    assert [bytes(a) for a in pkts] == [bytes(b) for b in again]


def test_rogue_router_and_ra_flood_steps_registered():
    from reforge.scenario.steps import STEPS
    assert "rogue_router" in STEPS and STEPS["rogue_router"].needs_root
    assert "ra_flood" in STEPS and STEPS["ra_flood"].attack == "T1498"


# --- §3.15: a modified packet queued behind a held one counts once ----------
def test_bridge_modified_counted_once_behind_held():
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    from reforge.core.bridge import UserspaceBridge
    from reforge.core.intercept import InterceptQueue
    from reforge.rules.actions import Hold, SetField
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    def frame(load):
        return bytes(Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5, dport=80) / load)

    eng = RuleEngine([
        Rule("hold", parse_filter('Raw.load contains "first"'), [Hold()]),
        Rule("mod", parse_filter('Raw.load contains "second"'), [SetField("IP", "ttl", 7)]),
    ])
    iq = InterceptQueue()
    br = UserspaceBridge("ifa", "ifb", eng, intercept=iq, armed=True)

    br._forward("ifa", frame(b"first"), lambda d: None)    # held
    br._forward("ifa", frame(b"second"), lambda d: None)   # modified, queued behind
    assert br.counters.modified == 0                       # nothing sent yet
    iq.resolve(iq.pending()[0].id, "forward", frame(b"first"))   # release the held one
    assert br.counters.modified == 1                       # 'second' counted exactly once


# --- §2.4: IMAP login parsing fixed + HTTP Digest capture -------------------
def test_imap_tagged_login_captured():
    from reforge.attacks.creds import CredentialExtractor
    ex = CredentialExtractor()
    creds = ex.extract_text("a1 LOGIN alice s3cr3t\r\n", "10.0.0.5", "10.0.0.9", 143, 40000)
    assert len(creds) == 1
    c = creds[0].as_dict()
    assert c["kind"] == "imap" and c["username"] == "alice" and c["secret"] == "s3cr3t"


def test_imap_authenticate_login_base64():
    import base64
    from reforge.attacks.creds import CredentialExtractor
    ex = CredentialExtractor()
    # AUTHENTICATE LOGIN then base64 user, base64 pass (same flow)
    u = base64.b64encode(b"bob").decode()
    p = base64.b64encode(b"hunter2").decode()
    creds = ex.extract_text(f"a2 AUTHENTICATE LOGIN\r\n{u}\r\n{p}\r\n",
                            "10.0.0.5", "10.0.0.9", 143, 40001)
    assert any(c.kind == "imap" and c.username == "bob" and c.secret == "hunter2"
               for c in creds)


def test_http_digest_captured():
    from reforge.attacks.creds import CredentialExtractor
    ex = CredentialExtractor()
    req = ('GET /secure HTTP/1.1\r\nHost: x\r\n'
           'Authorization: Digest username="carol", realm="test", '
           'response="abc123def456"\r\n\r\n')
    creds = ex.extract_text(req, "10.0.0.5", "10.0.0.9", 80, 40002)
    d = [c for c in creds if c.kind == "http-digest"]
    assert d and d[0].username == "carol" and d[0].secret == "abc123def456"
