"""TLS interception: dynamic CA, SNI parsing, STARTTLS strip, MITM loopback."""

from __future__ import annotations

import socket
import ssl
import struct
import threading

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from reforge.attacks import starttls
from reforge.attacks.tls_ca import DynamicCA
from reforge.attacks.tls_proxy import TlsInterceptor
from reforge.attacks.tls_sni import extract_sni
from reforge.core.apply import apply_engine
from reforge.rules import matchers as M
from reforge.rules import spec as S
from reforge.rules.base import Rule
from reforge.rules.engine import RuleEngine


# ---- dynamic CA ------------------------------------------------------------
def test_ca_mints_leaf_chaining_to_ca():
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    ca = DynamicCA()
    cert_pem, key_pem = ca.cert_for("secure.example.com")
    cert = x509.load_pem_x509_certificate(cert_pem)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "secure.example.com"
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "secure.example.com" in san.get_values_for_type(x509.DNSName)
    # leaf is signed by the CA
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate(ca.ca_pem()))


def test_ca_caches_per_host():
    ca = DynamicCA()
    assert ca.cert_for("a.test") == ca.cert_for("a.test")
    assert ca.cert_for("a.test") != ca.cert_for("b.test")


# ---- SNI parsing -----------------------------------------------------------
def _client_hello(host: str) -> bytes:
    h = host.encode()
    name = b"\x00" + struct.pack("!H", len(h)) + h          # host_name entry
    sni_ext_data = struct.pack("!H", len(name)) + name       # server_name_list
    sni_ext = struct.pack("!HH", 0x0000, len(sni_ext_data)) + sni_ext_data
    ext_block = struct.pack("!H", len(sni_ext)) + sni_ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"             # version, random, sid_len=0
            + struct.pack("!H", 2) + b"\x00\x2f"             # cipher suites
            + b"\x01\x00"                                    # compression
            + ext_block)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body   # handshake ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def test_extract_sni():
    assert extract_sni(_client_hello("mail.corp.local")) == "mail.corp.local"
    assert extract_sni(b"not a tls record") is None


# ---- STARTTLS strip --------------------------------------------------------
def test_strip_starttls_is_length_preserving():
    data = b"250-mail.corp\r\n250-STARTTLS\r\n250 SIZE\r\n"
    out, changed = starttls.strip_starttls(data)
    assert changed and len(out) == len(data)
    assert b"STARTTLS" not in out


def test_strip_starttls_action_via_engine():
    action = S.build_action({"type": "strip_starttls"})
    engine = RuleEngine([Rule("s", M.AllMatch(), [action])])
    raw = bytes(Ether() / IP() / TCP(sport=25, dport=40000) / b"250-STARTTLS\r\n250 OK\r\n")
    res = apply_engine(engine, raw)
    from scapy.packet import Raw
    assert res.modified
    assert b"STARTTLS" not in bytes(Ether(res.out)[Raw].load)


# ---- full TLS MITM loopback ------------------------------------------------
def test_tls_interception_decrypts_and_modifies():
    ca = DynamicCA()

    # upstream "real" TLS server (uses any cert; the interceptor won't verify it)
    up_ctx = ca.context_for("localhost")
    up_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    up_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up_srv.bind(("127.0.0.1", 0)); up_srv.listen(1)
    up_port = up_srv.getsockname()[1]

    def upstream():
        up_srv.settimeout(8)
        conn, _ = up_srv.accept()
        tconn = up_ctx.wrap_socket(conn, server_side=True)
        tconn.recv(4096)
        tconn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO")
        tconn.close()

    threading.Thread(target=upstream, daemon=True).start()

    def modify(data: bytes, from_client: bool) -> bytes:
        return data if from_client else data.replace(b"HELLO", b"PWNED")

    interceptor = TlsInterceptor(ca, listen=("127.0.0.1", 0),
                                 upstream_resolver=lambda sni: ("127.0.0.1", up_port),
                                 modify=modify)
    px_port = interceptor.start()
    try:
        cctx = ssl.create_default_context()
        cctx.load_verify_locations(cadata=ca.ca_pem().decode())   # victim trusts our CA
        raw = socket.create_connection(("127.0.0.1", px_port), timeout=8)
        tls = cctx.wrap_socket(raw, server_hostname="localhost")
        peer = tls.getpeercert()
        tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = b""
        while True:
            chunk = tls.recv(4096)
            if not chunk:
                break
            resp += chunk
        tls.close()
    finally:
        interceptor.stop()
        up_srv.close()

    # handshake succeeded against the FORGED cert, and the plaintext was modified
    assert b"PWNED" in resp
    subject = dict(x[0] for x in peer["subject"])
    assert subject.get("commonName") == "localhost"
    assert interceptor.intercepted == 1
