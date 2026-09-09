"""DHCP starvation/rogue + NDP spoof/rogue-RA packet builders."""

from __future__ import annotations

from reforge.attacks import dhcp, ndp


def _dhcp_type(pkt):
    from scapy.layers.dhcp import DHCP

    names = {"discover": 1, "offer": 2, "request": 3, "ack": 5}
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            v = opt[1]
            return names.get(v, v) if isinstance(v, str) else int(v)
    return None


def _dhcp_opt(pkt, name):
    from scapy.layers.dhcp import DHCP

    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == name:
            return opt[1]
    return None


# ---- DHCP ------------------------------------------------------------------
def test_discover_carries_client_mac():
    from scapy.layers.dhcp import BOOTP
    from scapy.utils import str2mac

    pkt = dhcp.build_discover("02:11:22:33:44:55", xid=0x1234)
    assert _dhcp_type(pkt) == 1                     # discover
    assert str2mac(pkt[BOOTP].chaddr[:6]) == "02:11:22:33:44:55"
    assert pkt[BOOTP].xid == 0x1234


def test_offer_and_ack_options():
    offer = dhcp.build_offer("02:11:22:33:44:55", 0x1234, "192.168.66.100",
                             "192.168.66.1", gateway="192.168.66.1", dns="192.168.66.1")
    from scapy.layers.dhcp import BOOTP

    assert _dhcp_type(offer) == 2                   # offer
    assert offer[BOOTP].yiaddr == "192.168.66.100"
    assert _dhcp_opt(offer, "router") == "192.168.66.1"
    assert _dhcp_opt(offer, "name_server") == "192.168.66.1"

    ack = dhcp.build_ack("02:11:22:33:44:55", 0x1234, "192.168.66.100", "192.168.66.1")
    assert _dhcp_type(ack) == 5                     # ack


def test_parse_request_roundtrip():
    disc = dhcp.build_discover("02:aa:bb:cc:dd:ee", xid=0x99)
    mac, xid, mtype = dhcp.parse_request(disc)
    assert mac == "02:aa:bb:cc:dd:ee" and xid == 0x99 and mtype == "discover"


def test_random_mac_is_locally_administered():
    m = dhcp.random_mac()
    first = int(m.split(":")[0], 16)
    assert first & 0x02                              # locally-administered bit set


# ---- NDP -------------------------------------------------------------------
def test_na_claims_target_at_our_mac():
    from scapy.layers.inet6 import ICMPv6ND_NA, ICMPv6NDOptDstLLAddr

    na = ndp.build_na("2001:db8::1", "ca:fe:ca:fe:00:01", "2001:db8::2")
    assert na[ICMPv6ND_NA].tgt == "2001:db8::1"
    assert int(na[ICMPv6ND_NA].O) == 1              # override
    assert na[ICMPv6NDOptDstLLAddr].lladdr == "ca:fe:ca:fe:00:01"


def test_rogue_ra_advertises_prefix_and_us():
    from scapy.layers.inet6 import ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr

    ra = ndp.build_ra("ca:fe:ca:fe:00:01", prefix="2001:db8:dead::")
    assert ra.haslayer(ICMPv6ND_RA) and int(ra[ICMPv6ND_RA].routerlifetime) > 0
    assert ra[ICMPv6NDOptSrcLLAddr].lladdr == "ca:fe:ca:fe:00:01"
    assert ra[ICMPv6NDOptPrefixInfo].prefix == "2001:db8:dead::"


def test_rogue_dhcp_offer_and_ack_use_the_same_ip():
    """DORA regression: the OFFER and the REQUEST's ACK must carry the same
    yiaddr for a client, or the handshake never completes."""
    import scapy.sendrecv as SR
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.l2 import Ether

    from reforge.attacks import dhcp as D

    sent = []
    orig = SR.sendp
    SR.sendp = lambda p, **k: sent.append(p)
    try:
        rogue = D.RogueDhcp("lo", "10.0.0.1", gateway="10.0.0.1", dns="10.0.0.1",
                            pool_base="10.0.0.", pool_start=200)
        mac = "02:11:22:33:44:55"
        rogue._on(Ether(bytes(D.build_discover(mac, xid=0x99))))
        req = Ether(bytes(D.build_discover(mac, xid=0x99)))
        for i, o in enumerate(req[DHCP].options):
            if isinstance(o, tuple) and o[0] == "message-type":
                req[DHCP].options[i] = ("message-type", 3)
        rogue._on(Ether(bytes(req)))
    finally:
        SR.sendp = orig
    yiaddrs = [p[BOOTP].yiaddr for p in sent if p.haslayer(BOOTP)]
    assert len(yiaddrs) == 2 and yiaddrs[0] == yiaddrs[1] == "10.0.0.200"
    assert rogue.leased == 1
