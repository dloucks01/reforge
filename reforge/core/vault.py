"""At-rest encryption for engagement artifacts.

Sessions, scenario reports, diagnostic bundles, and pcaps can hold harvested
credentials and network detail. This wraps them in authenticated encryption
(AES-256-GCM) with a key derived from a passphrase (scrypt), so an artifact at
rest is unreadable and tamper-evident without the passphrase.

Blob layout: MAGIC(5) | version(1) | salt(16) | nonce(12) | ciphertext+tag.
"""

from __future__ import annotations

import os
from pathlib import Path

MAGIC = b"RFGV1"
_VERSION = 1
_SALT = 16
_NONCE = 12


def _derive(passphrase: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def is_encrypted(data: bytes) -> bool:
    return data[:5] == MAGIC


def encrypt_bytes(data: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not passphrase:
        raise ValueError("a passphrase is required")
    salt = os.urandom(_SALT)
    nonce = os.urandom(_NONCE)
    ct = AESGCM(_derive(passphrase, salt)).encrypt(nonce, data, None)
    return MAGIC + bytes([_VERSION]) + salt + nonce + ct


def decrypt_bytes(blob: bytes, passphrase: str) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if not is_encrypted(blob):
        raise ValueError("not a Reforge vault blob")
    off = 6
    salt = blob[off:off + _SALT]; off += _SALT
    nonce = blob[off:off + _NONCE]; off += _NONCE
    ct = blob[off:]
    return AESGCM(_derive(passphrase, salt)).decrypt(nonce, ct, None)


def encrypt_file(src: str | Path, dst: str | Path, passphrase: str) -> Path:
    dst = Path(dst)
    dst.write_bytes(encrypt_bytes(Path(src).read_bytes(), passphrase))
    try:
        os.chmod(dst, 0o600)
    except OSError:
        pass
    return dst


def decrypt_file(src: str | Path, dst: str | Path, passphrase: str) -> Path:
    dst = Path(dst)
    dst.write_bytes(decrypt_bytes(Path(src).read_bytes(), passphrase))
    return dst
