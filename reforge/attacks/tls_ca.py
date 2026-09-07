"""Dynamic certificate authority for TLS interception.

Generates a throwaway root CA, then mints per-host leaf certificates signed by it
on demand (matching the requested SNI), so the interception proxy can present a
valid-looking certificate for any site. The victim must trust the CA (install
`ca_pem()` on the target) — standard for an authorized TLS-MITM engagement.

For authorized testing only.
"""

from __future__ import annotations

import atexit
import datetime
import ipaddress
import os
import shutil
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

_ONE_DAY = datetime.timedelta(days=1)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Reforge")])


class DynamicCA:
    def __init__(self, cn: str = "Reforge Root CA", key_size: int = 2048):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        now = datetime.datetime.now(datetime.timezone.utc)
        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(_name(cn)).issuer_name(_name(cn))
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                           critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        self._cert_cache: dict[str, tuple[bytes, bytes]] = {}
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        # 0700 dir (mkdtemp default) holds the per-host leaf keys ssl must load
        # from files; cleaned up on exit. The CA private key stays in memory and
        # is never written to disk.
        self._tmp = Path(tempfile.mkdtemp(prefix="reforge-tls-"))
        self._key_size = key_size
        atexit.register(self.close)

    def ca_pem(self) -> bytes:
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def _san(self, host: str) -> x509.SubjectAlternativeName:
        try:
            return x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))])
        except ValueError:
            return x509.SubjectAlternativeName([x509.DNSName(host)])

    def cert_for(self, host: str) -> tuple[bytes, bytes]:
        """Return (cert_pem, key_pem) for `host`, minted + signed by the CA."""
        if host in self._cert_cache:
            return self._cert_cache[host]
        key = rsa.generate_private_key(public_exponent=65537, key_size=self._key_size)
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(_name(host)).issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _ONE_DAY)
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(self._san(host), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False)
            .sign(self.ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption())
        self._cert_cache[host] = (cert_pem, key_pem)
        return cert_pem, key_pem

    def context_for(self, host: str) -> ssl.SSLContext:
        """A server-side SSLContext presenting the forged cert for `host`."""
        if host in self._ctx_cache:
            return self._ctx_cache[host]
        cert_pem, key_pem = self.cert_for(host)
        cert_f = self._tmp / f"{host}.crt"
        key_f = self._tmp / f"{host}.key"
        cert_f.write_bytes(cert_pem)
        key_f.write_bytes(key_pem)
        try:
            os.chmod(key_f, 0o600)          # restrict the private key explicitly
        except OSError:
            pass
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_f), str(key_f))
        self._ctx_cache[host] = ctx
        return ctx

    def write_ca(self, path: str | Path) -> Path:
        p = Path(path)
        p.write_bytes(self.ca_pem())
        return p

    def close(self) -> None:
        """Remove the temp dir holding the leaf private keys."""
        shutil.rmtree(self._tmp, ignore_errors=True)
