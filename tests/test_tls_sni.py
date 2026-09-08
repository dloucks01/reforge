"""TLS SNI extraction: valid ClientHello + robustness against malformed input.

The parser runs on attacker-supplied bytes, so every truncation/garbage input
must return None rather than raise."""

from __future__ import annotations

from reforge.attacks.tls_sni import extract_sni
from reforge.testlab.traffic import tls_client_hello


def test_extracts_sni_from_valid_client_hello():
    assert extract_sni(tls_client_hello("api.internal.corp")) == "api.internal.corp"


def test_non_handshake_record_is_none():
    assert extract_sni(b"\x17\x03\x03\x00\x05hello") is None      # app-data, not 0x16
    assert extract_sni(b"") is None
    assert extract_sni(b"\x16") is None                           # too short for header


def test_not_a_client_hello_is_none():
    # handshake record but type 0x02 (ServerHello), not 0x01
    assert extract_sni(b"\x16\x03\x01\x00\x04\x02\x00\x00\x00") is None


def test_truncated_client_hello_is_none_not_crash():
    full = tls_client_hello("host.example")
    # every prefix of a real ClientHello must parse to None or the name, never raise
    for cut in range(1, len(full)):
        out = extract_sni(full[:cut])
        assert out is None or out == "host.example"


def test_client_hello_without_sni_extension_is_none():
    # a ClientHello whose only extension is not server_name (0x0000)
    import struct
    ext = struct.pack("!HH", 0x000d, 2) + b"\x00\x00"        # signature_algorithms stub
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack("!H", len(ext)) + ext)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    assert extract_sni(rec) is None


def test_garbage_never_raises():
    import os
    for _ in range(200):
        blob = b"\x16\x03\x01" + os.urandom(40)
        extract_sni(blob)                                   # must not raise
