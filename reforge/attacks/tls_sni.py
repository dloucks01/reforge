"""Extract the SNI (server name) from a TLS ClientHello.

Lets the interceptor learn which host the victim is connecting to (to mint the
right certificate and pick the upstream) before completing the handshake. Pure
byte parsing — no scapy TLS layer needed.
"""

from __future__ import annotations

import struct


def extract_sni(data: bytes) -> str | None:
    try:
        # TLS record header: type(1)=0x16 handshake, version(2), length(2)
        if len(data) < 5 or data[0] != 0x16:
            return None
        pos = 5
        # Handshake header: type(1)=0x01 ClientHello, length(3)
        if data[pos] != 0x01:
            return None
        pos += 4
        pos += 2                      # client_version
        pos += 32                     # random
        sid_len = data[pos]; pos += 1 + sid_len
        cs_len = struct.unpack("!H", data[pos:pos + 2])[0]; pos += 2 + cs_len
        comp_len = data[pos]; pos += 1 + comp_len
        if pos + 2 > len(data):
            return None
        ext_total = struct.unpack("!H", data[pos:pos + 2])[0]; pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            etype, elen = struct.unpack("!HH", data[pos:pos + 4]); pos += 4
            if etype == 0x0000:       # server_name extension
                # server_name_list length(2), then entries: type(1)=host_name(0), len(2), name
                p = pos + 2
                if data[p] == 0x00:
                    nlen = struct.unpack("!H", data[p + 1:p + 3])[0]
                    return data[p + 3:p + 3 + nlen].decode("utf-8", "replace")
                return None
            pos += elen
    except Exception:
        return None
    return None
