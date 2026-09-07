"""Message-level interactive interception at the HTTP relay."""

from __future__ import annotations

import socket
import threading
import time

from reforge.attacks.http_relay import run_http_relay
from reforge.attacks.msg_intercept import MessageInterceptor
from reforge.core.intercept import InterceptQueue

REQ = b"POST /login HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nuser=admin"


def _hold_then(queue: InterceptQueue, action: str, new: bytes | None = None,
               timeout: float = 2.0):
    """Wait for one held item, then resolve it in a helper thread."""
    def run():
        deadline = time.time() + timeout
        while time.time() < deadline and queue.count() == 0:
            time.sleep(0.005)
        p = queue.pending()
        if p:
            queue.resolve(p[0].id, action, new)
    t = threading.Thread(target=run)
    t.start()
    return t


def test_should_hold_keyword_and_direction():
    mi = MessageInterceptor(InterceptQueue(), keyword="login", direction="requests")
    assert mi.should_hold(REQ, from_client=True)
    assert not mi.should_hold(REQ.replace(b"login", b"home"), from_client=True)
    assert not mi.should_hold(REQ, from_client=False)          # not a request
    mi2 = MessageInterceptor(InterceptQueue(), direction="responses")
    assert mi2.should_hold(b"HTTP/1.1 200 OK\r\n\r\n", from_client=False)


def test_process_holds_and_edits():
    q = InterceptQueue()
    mi = MessageInterceptor(q, keyword="login")
    edited = REQ.replace(b"admin", b"guest")
    t = _hold_then(q, "modify", edited)
    out = mi.process(REQ, True, ("c", 1))
    t.join()
    assert out == edited


def test_process_drop_returns_none():
    q = InterceptQueue()
    mi = MessageInterceptor(q, keyword="login")
    t = _hold_then(q, "drop")
    out = mi.process(REQ, True, ("c", 1))
    t.join()
    assert out is None


def test_process_passthrough_when_not_matching():
    q = InterceptQueue()
    mi = MessageInterceptor(q, keyword="nomatch")
    assert mi.process(REQ, True, ("c", 1)) == REQ
    assert q.count() == 0


def test_process_timeout_auto_forwards():
    q = InterceptQueue()
    mi = MessageInterceptor(q, keyword="login", hold_timeout=0.1)
    start = time.time()
    out = mi.process(REQ, True, ("c", 1))
    assert out == REQ and (time.time() - start) >= 0.08


def test_process_capacity_does_not_block():
    q = InterceptQueue(max_held=1)
    q.hold("x", b"filler", lambda o: None, flow_key=("z", 9))    # fill the cap
    mi = MessageInterceptor(q, keyword="login")
    assert mi.process(REQ, True, ("c", 2)) == REQ                # passes through, no block


def test_relay_holds_and_edits_end_to_end():
    client_relay, client_app = socket.socketpair()
    up_relay, up_app = socket.socketpair()
    q = InterceptQueue()
    mi = MessageInterceptor(q, keyword="login")
    rt = threading.Thread(target=run_http_relay,
                          args=(client_relay, up_relay, [], mi), daemon=True)
    rt.start()
    try:
        client_app.sendall(REQ)
        t = _hold_then(q, "modify", REQ.replace(b"admin", b"guest"))
        up_app.settimeout(2)
        got = up_app.recv(4096)
        t.join()
        assert b"user=guest" in got
    finally:
        for s in (client_relay, client_app, up_relay, up_app):
            s.close()


def test_interceptor_resolves_live_queue_via_provider():
    # a provider lets the proxy hold into whatever queue is currently live,
    # even after it is swapped (e.g. a bridge replaces it mid-session).
    current = {"q": InterceptQueue()}
    mi = MessageInterceptor(lambda: current["q"], keyword="login")
    assert mi.queue is current["q"]

    q1 = current["q"]
    t = _hold_then(q1, "forward")
    out = mi.process(REQ, True, ("c", 1))
    t.join()
    assert out == REQ

    current["q"] = InterceptQueue()                 # swap the live queue
    t2 = _hold_then(current["q"], "forward")
    mi.process(REQ, True, ("c", 2))
    t2.join()
    assert q1.count() == 0                           # not held into the old queue


def test_interceptor_none_queue_passes_through():
    mi = MessageInterceptor(lambda: None, keyword="login")
    assert mi.process(REQ, True, ("c", 1)) == REQ
