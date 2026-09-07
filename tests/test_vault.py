"""At-rest encryption for engagement artifacts."""

from __future__ import annotations

import pytest

from reforge.core import vault


def test_roundtrip():
    data = b"creds: admin:hunter2\nhosts: 10.0.0.0/24"
    blob = vault.encrypt_bytes(data, "correct horse battery staple")
    assert vault.is_encrypted(blob) and blob != data
    assert vault.decrypt_bytes(blob, "correct horse battery staple") == data


def test_wrong_passphrase_fails():
    blob = vault.encrypt_bytes(b"secret", "pass1")
    with pytest.raises(Exception):
        vault.decrypt_bytes(blob, "pass2")


def test_tamper_is_detected():
    blob = bytearray(vault.encrypt_bytes(b"secret data here", "pw"))
    blob[-1] ^= 0x01                       # flip a ciphertext/tag bit
    with pytest.raises(Exception):
        vault.decrypt_bytes(bytes(blob), "pw")


def test_not_a_vault_blob():
    assert not vault.is_encrypted(b"plain text")
    with pytest.raises(ValueError):
        vault.decrypt_bytes(b"plain text", "pw")


def test_file_roundtrip(tmp_path):
    src = tmp_path / "report.json"; src.write_text('{"creds": 1}')
    enc = tmp_path / "report.enc"; dec = tmp_path / "report.out"
    vault.encrypt_file(src, enc, "pw")
    assert vault.is_encrypted(enc.read_bytes())
    vault.decrypt_file(enc, dec, "pw")
    assert dec.read_text() == '{"creds": 1}'


def test_encrypted_session_roundtrip(tmp_path):
    from reforge.core.session import Session

    s = Session(name="engagement", notes="sensitive")
    p = tmp_path / "s.reforge"
    s.save(p, passphrase="pw")
    assert vault.is_encrypted(p.read_bytes())
    with pytest.raises(ValueError):
        Session.load(p)                    # encrypted, no passphrase
    loaded = Session.load(p, passphrase="pw")
    assert loaded.name == "engagement" and loaded.notes == "sensitive"
