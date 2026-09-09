"""Regression tests for wire-validity fixes (2026-09 code review §3.2, §3.9)."""

from __future__ import annotations

import ipaddress

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from reforge.attacks import dns_spoof, namepoison


def _is_unicast(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    return not (ip.is_multicast or ip.is_reserved) and addr != "255.255.255.255"


# --- §3.2: name-service poison answers must source from OUR unicast IP --------
def test_llmnr_response_source_is_our_ip():
    our_ip = "10.0.0.66"
    q = (IP(src="10.0.0.5", dst="224.0.0.252")
         / UDP(sport=50000, dport=5355)
         / DNS(qr=0, qd=DNSQR(qname="wpad")))
    resp = namepoison.build_response(q, our_ip)
    assert resp is not None
    assert resp[IP].src == our_ip                 # not the 224.0.0.252 multicast dst
    assert _is_unicast(resp[IP].src)
    assert resp[IP].dst == "10.0.0.5"             # still unicast back to the victim


def test_mdns_response_source_is_our_ip():
    our_ip = "10.0.0.66"
    q = (IP(src="10.0.0.9", dst="224.0.0.251")
         / UDP(sport=5353, dport=5353)
         / DNS(qr=0, qd=DNSQR(qname="printer.local")))
    resp = namepoison.build_response(q, our_ip)
    assert resp is not None and resp[IP].src == our_ip and _is_unicast(resp[IP].src)


# --- §3.9: DNS spoof honors query type and lowercases map keys ----------------
def _dns_query(qname, qtype):
    return (IP(src="10.0.0.5", dst="10.0.0.1")
            / UDP(sport=40000, dport=53)
            / DNS(qr=0, qd=DNSQR(qname=qname, qtype=qtype)))


def test_a_query_gets_a_record():
    resp = dns_spoof.spoof_response(_dns_query("evil.test", "A"), {"evil.test": "6.6.6.6"})
    assert resp is not None and resp[DNS].an[0].type == 1 and resp[DNS].an[0].rdata == "6.6.6.6"


def test_aaaa_query_with_v4_map_is_not_answered():
    # answering an AAAA query with an A record is discarded by the resolver
    resp = dns_spoof.spoof_response(_dns_query("evil.test", "AAAA"), {"evil.test": "6.6.6.6"})
    assert resp is None


def test_aaaa_query_gets_aaaa_record_from_v6_map():
    resp = dns_spoof.spoof_response(_dns_query("evil.test", "AAAA"), {"evil.test": "dead::beef"})
    assert resp is not None and resp[DNS].an[0].type == 28


def test_mixed_case_map_key_matches_exact():
    resp = dns_spoof.spoof_response(_dns_query("Evil.TEST", "A"), {"EVIL.test": "6.6.6.6"})
    assert resp is not None and resp[DNS].an[0].rdata == "6.6.6.6"
