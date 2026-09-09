"""Live verification of the guidance features (audit #4 and #5) on the real kernel.

Opt-in: sudo REFORGE_LIVE=1 python -m pytest tests/test_live_guidance.py -q

#4 (engine guidance) and #5 (message-proxy routing) are advisory: they don't move
packets, they tell the operator which path to take. So "live" here means proving
the *premise* each warning rests on is true on a real kernel:

  #5  A whole-HTTP-message transform (http_inject) run on the per-segment inline
      engine MISSES an injection whose marker lands in a later TCP segment — the
      exact silent no-op the warning describes — while the TcpProxy message relay,
      which reassembles the whole message, injects correctly on the same response.

  #4  recommend_inline_engine() reads the true host state (real interface count,
      real nfqueue stack) and points at the engine that actually works on this
      kernel: NFQUEUE when a MITM is live, a userspace bridge given two NICs. Both
      recommended engines are proven to manipulate live traffic elsewhere in the
      live suite (test_userspace_bridge_* / test_mitm_plus_nfqueue_*).
"""

from __future__ import annotations

import os
import socket
import subprocess
import textwrap
import threading
import time

import pytest

from reforge.testlab.netlab import BridgeFlowLab, SegmentLab, is_root, netns_exec

pytestmark = pytest.mark.skipif(
    not (is_root() and os.environ.get("REFORGE_LIVE") == "1"),
    reason="live guidance tests need root and REFORGE_LIVE=1",
)

INJECT = b"<!--INJECTED-BY-REFORGE-->"
MARKER = b"</body>"
# a body whose </body> marker sits well after a forced segment split
BODY = b"<html><body>PAGE-START-FILLER " + b"." * 40 + b" PAGE-END" + MARKER + b"</html>\n"
SPLIT = 30                       # send the body as two segments, split mid-body
HEAD = (b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
        b"Content-Length: " + str(len(BODY)).encode() + b"\r\nConnection: close\r\n\r\n")


def _two_segment_http_server(bind_ip: str, port: int) -> str:
    """Server source that sends HEAD+BODY[:SPLIT] then, after a pause, BODY[SPLIT:]
    — so the response is two TCP segments and </body> is only in the second."""
    return textwrap.dedent(f'''
        import socket, time
        HEAD={HEAD!r}; BODY={BODY!r}; SPLIT={SPLIT}
        s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(({bind_ip!r}, {port})); s.listen(1)
        c,_=s.accept()
        c.sendall(HEAD+BODY[:SPLIT]); time.sleep(0.4)     # segment 1: no </body>
        c.sendall(BODY[SPLIT:]); time.sleep(0.2)          # segment 2: carries </body>
        c.close()
    ''')


# --------------------------------------------------------------------------- #5
def test_per_segment_http_inject_mishandles_multisegment_body_live():
    """The #5 premise, live: an http_inject rule on the per-segment inline engine
    (the tool's userspace bridge) cannot place the injection correctly when </body>
    lands in a later segment. parse_http() only ever sees one segment, so the marker
    is never found in the segment that carries the body's tail — the snippet is
    dumped at the end of the first fragment instead of before </body> (its position
    depends on where TCP happened to split). Either way the correct placement
    (snippet immediately before </body>) is never produced — exactly what the
    warning steers the operator away from."""
    from reforge.attacks.http_actions import InjectHtml
    from reforge.core.bridge import UserspaceBridge
    from reforge.rules.base import Rule
    from reforge.rules.matchers import AllMatch
    from reforge.rules.engine import RuleEngine

    server = bridge = None
    with BridgeFlowLab() as lab:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-c",
                 _two_segment_http_server(lab["server_ip"], 9080)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.6)

            engine = RuleEngine([Rule("http-inject", AllMatch(),
                                      [InjectHtml(INJECT, MARKER)])])
            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], engine, armed=True,
                                     flow_rewrite=True)   # even with seqfix on, it can't help
            bridge.start()
            assert bridge.wait_ready(5.0), "bridge did not come up"

            cli = textwrap.dedent(f'''
                import socket, sys
                s=socket.socket(); s.settimeout(6); s.connect(({lab['server_ip']!r}, 9080))
                buf=b""
                try:
                    while True:
                        d=s.recv(4096)
                        if not d: break
                        buf+=d
                except Exception:
                    pass
                sys.stdout.buffer.write(buf)
            ''')
            r = netns_exec(lab["client_ns"], "python3", "-c", cli, check=False)
            got = r.stdout.encode() if isinstance(r.stdout, str) else r.stdout
        finally:
            if bridge is not None:
                bridge.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)

    # the whole body arrived, but the per-segment engine could not place the
    # injection correctly — the snippet is NOT immediately before </body>:
    assert b"PAGE-START-FILLER" in got and b"PAGE-END" in got, f"body truncated: {got!r}"
    assert INJECT + MARKER not in got, (
        "per-segment engine somehow placed the injection correctly (adjacent to "
        f"</body>) on a multi-segment body: {got!r}")


def test_message_relay_injects_the_same_multisegment_body_live():
    """The #5 recommendation, live: the TcpProxy message relay reassembles the same
    two-segment response and DOES inject before </body> — what the warning points at."""
    from reforge.attacks import tcp_proxy

    # a raw two-segment HTTP server on loopback
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    srv_port = srv.getsockname()[1]

    def serve():
        try:
            c, _ = srv.accept()
            c.sendall(HEAD + BODY[:SPLIT]); time.sleep(0.4)
            c.sendall(BODY[SPLIT:]); time.sleep(0.2)
            c.close()
        except Exception:
            pass

    t = threading.Thread(target=serve, daemon=True); t.start()

    proxy = tcp_proxy.TcpProxy(lambda c: ("127.0.0.1", srv_port),
                               http_transforms=[tcp_proxy.inject(INJECT, MARKER)],
                               listen=("127.0.0.1", 0))
    port = proxy.start()
    try:
        cs = socket.socket(); cs.settimeout(6); cs.connect(("127.0.0.1", port))
        cs.sendall(b"GET /page.html HTTP/1.0\r\nHost: x\r\n\r\n")
        buf = b""
        while True:
            d = cs.recv(4096)
            if not d:
                break
            buf += d
        cs.close()
    finally:
        proxy.stop()
        srv.close()

    # the relay reassembled the whole message, so the snippet lands exactly where
    # http_inject means it to: immediately before </body> (adjacent), the correct
    # placement the per-segment path above could not produce.
    assert INJECT + MARKER in buf, (
        f"message relay did not inject immediately before </body>: {buf!r}")


# --------------------------------------------------------------------------- #4
def test_engine_recommendation_matches_live_host_state():
    """The #4 premise, live: recommend_inline_engine reads the real interface count
    and the real nfqueue stack, and points at the engine that works on THIS kernel."""
    from reforge.capture.registry import list_interfaces
    from reforge.diagnostics.doctor import check_nfqueue_ready, recommend_inline_engine

    with SegmentLab():
        # the live lab attaches several veths -> a real multi-NIC host
        ifaces = [i for i in list_interfaces() if i not in ("lo", "<none>", "af_packet")]
        n = len(ifaces)
        assert n >= 2, f"expected >=2 live interfaces, saw {ifaces}"

        # this kernel really does have the NFQUEUE stack (the live MITM+NFQUEUE
        # test relies on it), so the recommender must see it as ready
        nfq = check_nfqueue_ready()
        assert nfq.ok, f"nfqueue stack not ready on this host: {nfq.detail}"

        # a live MITM -> NFQUEUE (the engine proven by test_mitm_plus_nfqueue_*)
        assert recommend_inline_engine(n, nfq.ok, mitm_active=True).engine == "nfqueue"
        # two NICs, no MITM -> a transparent bridge (proven by test_userspace_bridge_*)
        adv = recommend_inline_engine(n, nfq.ok, mitm_active=False)
        assert adv.engine == "bridge" and "L3 footprint" in adv.reason
