"""New credential harvesters: LDAP simple bind, Telnet, NTLM (NetNTLM hashes),
Kerberos AS-REQ pre-auth (2026-09 review §2.4 remainder)."""

from __future__ import annotations

import base64

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from reforge.attacks.creds import CredentialExtractor


# --- tiny DER encoder for building ASN.1 fixtures ---------------------------
def der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def _pkt(src, sport, dst, dport, payload, proto=TCP):
    return Ether() / IP(src=src, dst=dst) / proto(sport=sport, dport=dport) / Raw(payload)


# --- LDAP simple bind -------------------------------------------------------
def test_ldap_simple_bind():
    bind = der(0x60,                                    # BindRequest [APPLICATION 0]
               der(0x02, b"\x03")                       # version
               + der(0x04, b"cn=admin,dc=corp,dc=local")  # name
               + der(0x80, b"S3cr3t!"))                 # simple [0] password
    msg = der(0x30, der(0x02, b"\x01") + bind)          # LDAPMessage
    ex = CredentialExtractor()
    creds = ex.extract(_pkt("10.0.0.5", 40000, "10.0.0.9", 389, msg))
    ld = [c for c in creds if c.kind == "ldap"]
    assert ld and ld[0].username == "cn=admin,dc=corp,dc=local" and ld[0].secret == "S3cr3t!"


def test_ldap_anonymous_bind_ignored():
    bind = der(0x60, der(0x02, b"\x03") + der(0x04, b"") + der(0x80, b""))
    msg = der(0x30, der(0x02, b"\x01") + bind)
    ex = CredentialExtractor()
    assert [c for c in ex.extract(_pkt("10.0.0.5", 40000, "10.0.0.9", 389, msg))
            if c.kind == "ldap"] == []


# --- Telnet -----------------------------------------------------------------
def test_telnet_login_captured():
    ex = CredentialExtractor()
    S, C, cp = "10.0.0.9", "10.0.0.5", 55555
    ex.extract(_pkt(S, 23, C, cp, b"\xff\xfb\x01login: "))    # prompt (with an IAC)
    ex.extract(_pkt(C, cp, S, 23, b"alice\r\n"))
    ex.extract(_pkt(S, 23, C, cp, b"Password: "))
    creds = ex.extract(_pkt(C, cp, S, 23, b"hunter2\r\n"))
    tn = [c for c in creds if c.kind == "telnet"]
    assert tn and tn[0].username == "alice" and tn[0].secret == "hunter2"


def test_telnet_char_at_a_time():
    ex = CredentialExtractor()
    S, C, cp = "10.0.0.9", "10.0.0.5", 55556
    ex.extract(_pkt(S, 23, C, cp, b"login: "))
    for ch in b"bob\r":                                      # one keystroke per packet
        ex.extract(_pkt(C, cp, S, 23, bytes([ch])))
    ex.extract(_pkt(S, 23, C, cp, b"Password: "))
    creds = []
    for ch in b"pw123\r":
        creds += ex.extract(_pkt(C, cp, S, 23, bytes([ch])))
    tn = [c for c in creds if c.kind == "telnet"]
    assert tn and tn[0].username == "bob" and tn[0].secret == "pw123"


# --- NTLM over HTTP ---------------------------------------------------------
def _ntlm_type2(challenge: bytes) -> bytes:
    return (b"NTLMSSP\x00" + (2).to_bytes(4, "little")
            + b"\x00" * 8 + b"\x00" * 4 + challenge + b"\x00" * 8)


def _ntlm_type3(user: str, domain: str, nt: bytes, lm: bytes = b"\x00" * 24) -> bytes:
    u = user.encode("utf-16-le")
    d = domain.encode("utf-16-le")
    header_len = 64
    payload = b""

    def add(data):
        nonlocal payload
        off = header_len + len(payload)
        sb = len(data).to_bytes(2, "little") * 2 + off.to_bytes(4, "little")
        payload += data
        return sb

    lm_sb, nt_sb, dom_sb, user_sb = add(lm), add(nt), add(d), add(u)
    empty = (0).to_bytes(2, "little") * 2 + header_len.to_bytes(4, "little")
    return (b"NTLMSSP\x00" + (3).to_bytes(4, "little")
            + lm_sb + nt_sb + dom_sb + user_sb + empty + empty + b"\x00" * 4 + payload)


def test_ntlm_v2_hash_over_http():
    ex = CredentialExtractor()
    S, C, cp = "10.0.0.9", "10.0.0.5", 44444
    chal = bytes.fromhex("1122334455667788")
    t2 = base64.b64encode(_ntlm_type2(chal)).decode()
    ex.extract(_pkt(S, 80, C, cp, f"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM {t2}\r\n\r\n".encode()))

    nt = b"\x11" * 16 + b"\x22" * 30                        # v2: 16 proof + blob
    t3 = base64.b64encode(_ntlm_type3("alice", "CORP", nt)).decode()
    creds = ex.extract(_pkt(C, cp, S, 80, f"GET / HTTP/1.1\r\nAuthorization: NTLM {t3}\r\n\r\n".encode()))
    nt_creds = [c for c in creds if c.kind == "ntlm"]
    assert nt_creds
    c = nt_creds[0]
    assert c.username == "CORP\\alice"
    assert c.secret.startswith("alice::CORP:1122334455667788:")
    assert "5600" in c.detail                               # hashcat NetNTLMv2 mode


# --- Kerberos AS-REQ pre-auth ----------------------------------------------
def test_kerberos_as_req_preauth():
    enc = der(0x30, der(0xA0, der(0x02, bytes([23])))       # EncryptedData: etype 23
             + der(0xA2, der(0x04, b"\xAA" * 44)))          #   cipher
    padata_item = der(0x30, der(0xA1, der(0x02, bytes([2])))  # padata-type 2
                      + der(0xA2, der(0x04, enc)))          # padata-value
    padata = der(0xA3, der(0x30, padata_item))              # padata [3] SEQ OF
    principal = der(0x30, der(0xA0, der(0x02, bytes([1])))  # name-type
                    + der(0xA1, der(0x30, der(0x1B, b"alice"))))  # name-string
    reqbody = der(0xA4, der(0x30, der(0xA1, principal)      # cname [1]
                            + der(0xA2, der(0x1B, b"CORP.LOCAL"))))  # realm [2]
    asreq = der(0x6A, der(0x30, padata + reqbody))          # AS-REQ [APPLICATION 10]

    ex = CredentialExtractor()
    creds = ex.extract(_pkt("10.0.0.5", 40000, "10.0.0.9", 88, asreq, proto=UDP))
    kb = [c for c in creds if c.kind == "kerberos"]
    assert kb
    assert kb[0].username == "alice@CORP.LOCAL"
    assert kb[0].secret.startswith("$krb5pa$23$alice$CORP.LOCAL$aaaaaa")
    assert "7500" in kb[0].detail
