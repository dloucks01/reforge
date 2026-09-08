"""Name-service poisoning: LLMNR/mDNS query detection + poisoned responses."""

from __future__ import annotations

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from reforge.attacks import namepoison as N


def _llmnr_query(name="wpad", src="10.0.0.50", port=5355):
    return IP(src=src, dst="224.0.0.252") / UDP(sport=55000, dport=port) / \
        DNS(id=0x1234, rd=1, qd=DNSQR(qname=name))


def test_queried_name_llmnr_and_mdns():
    assert N.queried_name(_llmnr_query("fileserver")).rstrip(".") == "fileserver"
    assert N.queried_name(_llmnr_query("printer", port=5353)).rstrip(".") == "printer"


def test_queried_name_ignores_non_query_and_wrong_port():
    resp = IP() / UDP(dport=5355) / DNS(qr=1, qd=DNSQR(qname="x"))
    assert N.queried_name(resp) is None                     # a response, not a query
    dns53 = IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="x"))
    assert N.queried_name(dns53) is None                    # ordinary DNS port


def test_build_response_answers_with_our_ip():
    q = _llmnr_query("wpad", src="10.0.0.50")
    resp = N.build_response(q, "10.0.0.66")
    assert resp is not None
    assert resp[IP].dst == "10.0.0.50"                      # back to the querier
    assert resp[DNS].qr == 1 and resp.haslayer(DNSRR)
    assert resp[DNSRR].rdata == "10.0.0.66"                 # points the victim at us
    assert resp[UDP].sport == 5355


def test_build_response_ttls_differ_llmnr_vs_mdns():
    llmnr = N.build_response(_llmnr_query(port=5355), "10.0.0.66")
    mdns = N.build_response(_llmnr_query(port=5353), "10.0.0.66")
    assert llmnr[DNSRR].ttl == 30 and mdns[DNSRR].ttl == 120


def test_build_response_none_for_ordinary_dns():
    assert N.build_response(IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="x")), "1.1.1.1") is None


def test_nbtns_query_detected_and_response_safe():
    from scapy.layers.netbios import NBNSQueryRequest
    q = IP(src="10.0.0.50", dst="10.0.0.255") / UDP(sport=50000, dport=137) / \
        NBNSQueryRequest(QUESTION_NAME="FILESERVER")
    name = N.queried_name(q)
    assert name is not None and "FILESERVER" in name.upper()   # NBT-NS query detected
    # response crafting must never raise (returns a response or None on this stack)
    resp = N.build_response(q, "10.0.0.66")
    assert resp is None or resp[UDP].sport == 137
