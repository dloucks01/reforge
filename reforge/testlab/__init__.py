"""Self-contained test lab: synthetic traffic, a replay backend, and demo data.

Lets the whole tool — bridge, intercept, reassembly, credential harvest, recon,
scan — be exercised end to end without a NIC or root, both in tests and live in
the GUI via a synthetic capture backend.
"""

from reforge.testlab.traffic import (
    arp_who_has,
    dns_lookup,
    ftp_login,
    http_large_response,
    http_login,
    mixed_scenario,
    tcp_flow,
)

__all__ = [
    "arp_who_has",
    "dns_lookup",
    "ftp_login",
    "http_large_response",
    "http_login",
    "mixed_scenario",
    "tcp_flow",
]
