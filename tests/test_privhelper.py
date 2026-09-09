"""Privileged helper: full op set + client round-trip (2026-09 review §2.1).

All ops run in plan mode (apply=False), so nothing privileged executes and the
tests need no root — they prove the IPC contract and command planning."""

from __future__ import annotations

import socket
import threading

from reforge.privhelper.helper import Helper
from reforge.privhelper.ipc import HelperClient, decode_line, encode


# ---- handle() covers every advertised op -----------------------------------
def test_handle_ping():
    r = Helper().handle({"op": "ping", "args": {}})
    assert r["ok"] and "pid" in r["data"]


def test_handle_prepare_bridge_plans_both_ifaces():
    r = Helper().handle({"op": "prepare_bridge",
                         "args": {"if_a": "eth0", "if_b": "eth1", "apply": False}})
    assert r["ok"]
    flat = [" ".join(c) for c in r["data"]["planned"]]
    assert any("ethtool -K eth0" in c for c in flat)
    assert any("ethtool -K eth1" in c for c in flat)
    # host-stack suppression is part of bridge prep, in the arp family
    assert any(c.startswith("nft add table arp reforge") for c in flat)


def test_handle_queue_install_and_remove_plan():
    h = Helper()
    r = h.handle({"op": "queue_install", "args": {"queue_num": 2, "apply": False}})
    assert r["ok"]
    flat = [" ".join(c) for c in r["data"]["planned"]]
    assert any("queue num 2" in c for c in flat)
    assert r["data"]["remove"]                      # a teardown command is returned
    assert h.handle({"op": "queue_remove", "args": {"apply": False}})["ok"]


def test_handle_fail_open_and_closed():
    h = Helper()
    assert h.handle({"op": "fail_open", "args": {"if_a": "eth0", "if_b": "eth1"}})["ok"]
    assert h.handle({"op": "fail_closed", "args": {"if_a": "eth0", "if_b": "eth1"}})["ok"]


def test_handle_unknown_op():
    r = Helper().handle({"op": "nope", "args": {}})
    assert not r["ok"] and "unknown op" in r["error"]


def test_handle_bad_args_does_not_crash():
    r = Helper().handle({"op": "prepare_bridge", "args": {}})   # missing if_a/if_b
    assert not r["ok"] and r["error"]


# ---- client <-> helper over a real Unix socket -----------------------------
def _serve_one(sock_path: str, helper: Helper, ready: threading.Event) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as srv:
        srv.bind(sock_path)
        srv.listen(1)
        ready.set()                              # only now is connect() accepted
        conn, _ = srv.accept()
        with conn:
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            conn.sendall(encode(helper.handle(decode_line(buf))))


def test_client_roundtrip_over_socket(tmp_path):
    sock_path = str(tmp_path / "h.sock")
    ready = threading.Event()
    t = threading.Thread(target=_serve_one, args=(sock_path, Helper(), ready), daemon=True)
    t.start()
    assert ready.wait(2.0), "server never reached listen()"

    client = HelperClient(sock_path=sock_path)
    assert client.available()
    resp = client.prepare_bridge("eth0", "eth1", apply=False)
    assert resp.ok and resp.data["planned"]
    t.join(2.0)


def test_client_available_false_when_no_socket(tmp_path):
    assert HelperClient(sock_path=str(tmp_path / "absent.sock")).available() is False
