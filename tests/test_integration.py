"""End-to-end integration through the real pipeline using the synthetic lab.

Exercises reassembly, credential harvest, recon inventory, the intercept bridge,
and the synthetic capture backend together — no NIC, no root.
"""

from __future__ import annotations

import time

from scapy.layers.l2 import Ether

from reforge.attacks.creds import CredentialExtractor
from reforge.attacks.stream_harvester import StreamHarvester
from reforge.core.bridge import UserspaceBridge
from reforge.core.capture_service import CaptureService
from reforge.core.intercept import InterceptQueue
from reforge.core.tcpreasm import TcpReassembler
from reforge.recon.assets import AssetInventory
from reforge.rules.actions import Hold
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine
from reforge.rules.filter import parse_filter
from reforge.testlab import traffic as T
from reforge.testlab.synthetic import SyntheticBackend


# ---- reassembly -----------------------------------------------------------
def test_login_stream_reassembles_exactly():
    frames = T.http_login(user="admin", password="s3cr3t")
    tr = TcpReassembler()
    streams: dict = {}
    for _ts, fb in frames:
        for key, data in tr.process(Ether(fb)):
            streams[key] = streams.get(key, b"") + data
    client = next(v for k, v in streams.items() if k[3] == 80)
    assert b"POST /login" in client and b"password=s3cr3t" in client


def test_large_response_reassembles_full_body():
    frames = T.http_large_response(body_size=8000)
    tr = TcpReassembler()
    streams: dict = {}
    for _ts, fb in frames:
        for key, data in tr.process(Ether(fb)):
            streams[key] = streams.get(key, b"") + data
    server = next(v for k, v in streams.items() if k[1] == 80)
    assert server.count(b"A") == 8000


# ---- credential harvest ---------------------------------------------------
def _harvest(frames):
    ce, sh = CredentialExtractor(), StreamHarvester()
    found = []
    for _ts, fb in frames:
        found += ce.extract(Ether(fb))
        found += sh.add_frame(fb)
    return found


def test_http_login_yields_basic_and_form_creds():
    users = {(c.kind, c.username) for c in _harvest(T.http_login(user="admin", password="pw"))}
    assert ("http-basic", "admin") in users
    assert ("http-form", "admin") in users


def test_ftp_login_yields_cleartext_creds():
    creds = _harvest(T.ftp_login(user="ftpuser", password="ftppass"))
    assert any(c.kind == "ftp" and c.username == "ftpuser" and c.secret == "ftppass"
               for c in creds)


def test_mixed_scenario_harvests_multiple_identities():
    users = {c.username for c in _harvest(T.mixed_scenario()) if c.username}
    assert {"admin", "bob", "ftpuser"} <= users


# ---- recon inventory ------------------------------------------------------
def test_mixed_scenario_builds_inventory():
    inv = AssetInventory()
    for _ts, fb in T.mixed_scenario():
        try:
            inv.observe(Ether(fb))
        except Exception:
            pass
    ips = {h.ip for h in inv.list_hosts()}
    assert {"10.0.0.10", "10.0.0.50"} <= ips


# ---- intercept bridge over synthetic traffic ------------------------------
def test_bridge_holds_and_edits_a_synthetic_login():
    engine = RuleEngine([Rule("hold", parse_filter('Raw.load contains "password"'), [Hold()])])
    iq = InterceptQueue()
    br = UserspaceBridge("labA", "labB", engine, intercept=iq, armed=True)
    egress: list = []
    for _ts, fb in T.http_login(user="admin", password="s3cr3t"):
        br._forward("labA", fb, egress.append)
    assert iq.count() >= 1                               # the login segment is held
    # edit the held login and release everything
    for hp in iq.pending():
        iq.resolve(hp.id, "modify", hp.data.replace(b"s3cr3t", b"REDACTED"))
    joined = b"".join(egress)
    assert b"REDACTED" in joined and b"s3cr3t" not in joined


# ---- synthetic capture backend through the service ------------------------
def test_synthetic_backend_feeds_capture_service():
    svc = CaptureService(SyntheticBackend(speed=500.0))
    svc.start()
    got = 0
    for _ in range(50):
        got += len(svc.drain())
        if not svc.running:
            break
        time.sleep(0.02)
    svc.stop()
    assert got > 20 and svc.error is None
