"""Mutual TLS for the distributed transport.

Wraps the collector↔sensor connection in TLS with client-certificate auth, so an
attacker who reaches the collector port can neither read reported credentials nor
inject observations without a trusted client cert.

`server_context`/`client_context` build contexts from real cert/key/CA files.
`dev_mtls()` mints a throwaway CA + collector (server) + sensor (client) cert for
a quick self-contained setup (and the tests).
"""

from __future__ import annotations

import os
import ssl
import tempfile
from pathlib import Path


def server_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.verify_mode = ssl.CERT_REQUIRED         # require a client certificate
    ctx.load_verify_locations(cafile)
    return ctx


def client_context(certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_cert_chain(certfile, keyfile)
    ctx.load_verify_locations(cafile)
    ctx.check_hostname = False                  # verified by CA + client cert, not SNI
    return ctx


def dev_mtls(ca=None):
    """Return (server_ctx, client_ctx, ca) for a self-contained mTLS setup."""
    from reforge.attacks.tls_ca import DynamicCA

    ca = ca or DynamicCA()
    d = Path(tempfile.mkdtemp(prefix="reforge-mtls-"))

    def _w(name: str, data: bytes) -> str:
        p = d / name
        p.write_bytes(data)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return str(p)

    ca_pem = _w("ca.pem", ca.ca_pem())
    scert, skey = ca.cert_for("collector")
    ccert, ckey = ca.cert_for("sensor")
    server_ctx = server_context(_w("s.crt", scert), _w("s.key", skey), ca_pem)
    client_ctx = client_context(_w("c.crt", ccert), _w("c.key", ckey), ca_pem)
    return server_ctx, client_ctx, ca
