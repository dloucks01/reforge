"""Wire-facing parsers must never raise on hostile input (never break the wire).

The bridge/NFQUEUE inline path and the sniff-loop attack callbacks all run these
over attacker/victim-controlled bytes; a raised exception would break forwarding
or kill the attack thread."""

from __future__ import annotations

import os
import random

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether

# A DNS query whose question section is corrupt enough that scapy dissects the
# qd as a bare Raw (no .qname) — the exact shape that used to raise AttributeError.
_MALFORMED_DNS = bytes.fromhex(
    "ffffffffffff000000000000080045000033000100004011e3b77f0000017f00f2"
    "0100350035001f8a1100000100000100b100000000016103636f6d6100010001")


def test_dns_spoof_malformed_question_returns_none():
    from reforge.attacks.dns_spoof import spoof_response
    assert spoof_response(Ether(_MALFORMED_DNS), {"*": "1.1.1.1"}) is None


def test_namepoison_malformed_question_returns_none():
    from reforge.attacks import namepoison as N
    pkt = Ether(_MALFORMED_DNS)
    assert N.queried_name(pkt) is None
    assert N.build_response(pkt, "10.0.0.66") is None


def test_parsers_never_raise_on_dissectable_fuzz():
    """Mutate a valid DNS query many ways; the parsers must return, never raise."""
    from reforge.attacks import namepoison as N
    from reforge.attacks.creds import CredentialExtractor
    from reforge.attacks.dns_spoof import spoof_response
    from reforge.recon.assets import AssetInventory
    from reforge.recon.fingerprint import os_from_syn, service_from_packet

    rng = random.Random(2)
    base = bytes(Ether() / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.com")))
    pkts = [Ether() / IP() / UDP(dport=137) / os.urandom(20),
            Ether() / IP() / ICMP() / os.urandom(40),
            Ether() / IP(proto=99) / os.urandom(20),
            Ether() / IP() / TCP(dport=80)]
    for _ in range(300):
        b = bytearray(base)
        for _ in range(rng.randint(1, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        try:
            pkts.append(Ether(bytes(b)))
        except Exception:  # noqa: BLE001, S110 - fuzz corpus
            pass

    ce, inv = CredentialExtractor(), AssetInventory()
    for p in pkts:                       # not a single call may raise
        spoof_response(p, {"*": "1.1.1.1"})
        N.queried_name(p)
        N.build_response(p, "10.0.0.66")
        ce.extract(p)
        inv.observe(p)
        os_from_syn(p)
        service_from_packet(p)


def test_dhcp_parse_request_never_raises_on_fuzz():
    from reforge.attacks import dhcp
    rng = random.Random(4)
    base = bytes(dhcp.build_discover("02:aa:bb:cc:dd:ee", xid=0x99))
    pkts = []
    for _ in range(400):
        b = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        try:
            pkts.append(Ether(bytes(b)))
        except Exception:  # noqa: BLE001, S110 - fuzz corpus
            pass
    for p in pkts:
        dhcp.parse_request(p)            # must return (mac,xid,type) or None, never raise


def test_stream_harvester_and_msg_intercept_never_raise():
    from reforge.attacks.msg_intercept import MessageInterceptor
    from reforge.attacks.stream_harvester import StreamHarvester
    from reforge.core.intercept import InterceptQueue

    sh = StreamHarvester()
    mi = MessageInterceptor(InterceptQueue(), keyword="password")
    good = bytes(Ether() / IP() / TCP(dport=80) / __import__("scapy.packet", fromlist=["Raw"]).Raw(
        b"POST /login HTTP/1.1\r\nAuthorization: Basic YWRtaW46cA==\r\n\r\n"))
    corpus = [os.urandom(random.Random(5).randint(0, 100)) for _ in range(200)]
    corpus += [good[:c] for c in range(0, len(good), 5)] + [b"", b"\xff" * 1500]
    for b in corpus:
        sh.add_frame(b)
        mi.process(b, True, ("f", 1))
        mi.should_hold(b, True)
