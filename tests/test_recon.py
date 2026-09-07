"""Passive recon: OS fingerprinting, service detection, asset inventory."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.recon import fingerprint as fp
from reforge.recon.assets import AssetInventory


def _syn(ttl, opts, win=64240, src="10.0.0.5"):
    return Ether() / IP(src=src, dst="10.0.0.1", ttl=ttl) / TCP(dport=80, flags="S",
                                                                window=win, options=opts)


# ---- OS fingerprint --------------------------------------------------------
def test_linux_syn():
    g = fp.os_from_syn(_syn(64, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                                 ("NOP", None), ("WScale", 7)]))
    assert g and g.family == "Linux" and g.confidence == "high"
    assert g.initial_ttl == 64 and g.mss == 1460


def test_windows_syn():
    g = fp.os_from_syn(_syn(128, [("MSS", 1460), ("NOP", None), ("WScale", 8),
                                  ("NOP", None), ("NOP", None), ("SAckOK", b"")]))
    assert g and g.family == "Windows"
    assert g.initial_ttl == 128


def test_ttl_decremented_by_hops_still_classifies():
    # TTL 52 (Linux 64 minus 12 hops) still rounds up to initial 64
    g = fp.os_from_syn(_syn(52, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                                 ("WScale", 7)]))
    assert g.initial_ttl == 64


def test_syn_ack_is_not_fingerprinted():
    pkt = Ether() / IP(ttl=64) / TCP(flags="SA")
    assert fp.os_from_syn(pkt) is None


# ---- service detection -----------------------------------------------------
def test_ssh_banner():
    pkt = Ether() / IP(src="10.0.0.9") / TCP(sport=22) / b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n"
    svcs = fp.service_from_packet(pkt)
    assert svcs and svcs[0].service == "ssh" and "OpenSSH_9.6p1" in svcs[0].version


def test_http_server_header():
    pkt = Ether() / IP(src="10.0.0.9") / TCP(sport=80) / \
        b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\n\r\n"
    svcs = fp.service_from_packet(pkt)
    assert svcs and svcs[0].service == "http" and svcs[0].version == "nginx/1.25.3"


# ---- asset inventory -------------------------------------------------------
def test_inventory_accumulates():
    inv = AssetInventory()
    inv.observe(_syn(64, [("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)),
                          ("WScale", 7)], src="10.0.0.5"))
    inv.observe(Ether() / IP(src="10.0.0.9") / TCP(sport=22) / b"SSH-2.0-OpenSSH_9.6\r\n")
    inv.observe(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(dport=443) /
                b"GET / HTTP/1.1\r\nHost: intranet.corp\r\n\r\n")

    hosts = {h.ip: h for h in inv.list_hosts()}
    assert hosts["10.0.0.5"].os_family == "Linux"
    assert "intranet.corp" in hosts["10.0.0.5"].hostnames
    assert hosts["10.0.0.9"].services.get(22, "").startswith("ssh")
