"""Built-in custom dissectors for industrial / OT + a few niche protocols.

Scapy dissects the mainstream stack; these ship the header layouts for common
ICS/OT protocols that an inline operator wants to *manipulate field-by-field*
(function codes, unit ids, lengths, transaction ids) but that Scapy doesn't bind
by default. Each is a declarative spec — the exact same format an operator uses
for a proprietary protocol — so it flows through the whole tool identically:

- `define_protocol` builds a Scapy layer + binds it to its port(s), so the packet
  tree, field-level rules, and the builder all understand it.
- `SpecDissector` registers it in the `dissect` registry with an editable,
  offset-accurate field layout.

Header-level by design (the payloads are protocol-specific and large); that is
exactly the part inline manipulation targets. "All protocols matter."
"""

from __future__ import annotations

import logging

log = logging.getLogger("reforge.dissect.builtins")

# Each spec mirrors craft.custom_proto's format. `bind.ports` binds both
# directions so requests and responses dissect alike.
BUILTIN_SPECS: list[dict] = [
    {
        "name": "ModbusTCP",                    # MBAP header (Modbus/TCP)
        "fields": [
            {"name": "transaction_id", "type": "u16"},
            {"name": "protocol_id", "type": "u16"},
            {"name": "length", "type": "u16"},
            {"name": "unit_id", "type": "u8"},
            {"name": "function_code", "type": "u8"},
            {"name": "data", "type": "rest"},
        ],
        "bind": {"over": "TCP", "ports": [502]},
    },
    {
        "name": "DNP3",                         # DNP3 data-link header
        "fields": [
            {"name": "start", "type": "u16"},   # 0x0564
            {"name": "length", "type": "u8"},
            {"name": "control", "type": "u8"},
            {"name": "destination", "type": "u16le"},
            {"name": "source", "type": "u16le"},
            {"name": "payload", "type": "rest"},
        ],
        "bind": {"over": "TCP", "ports": [20000]},
    },
    {
        "name": "BACnetIP",                     # BACnet/IP BVLC header
        "fields": [
            {"name": "bvlc_type", "type": "u8"},    # 0x81
            {"name": "bvlc_function", "type": "u8"},
            {"name": "bvlc_length", "type": "u16"},
            {"name": "npdu", "type": "rest"},
        ],
        "bind": {"over": "UDP", "ports": [47808]},
    },
    {
        "name": "IEC104",                       # IEC 60870-5-104 APCI
        "fields": [
            {"name": "start", "type": "u8"},    # 0x68
            {"name": "apdu_length", "type": "u8"},
            {"name": "control1", "type": "u8"},
            {"name": "control2", "type": "u8"},
            {"name": "control3", "type": "u8"},
            {"name": "control4", "type": "u8"},
            {"name": "asdu", "type": "rest"},
        ],
        "bind": {"over": "TCP", "ports": [2404]},
    },
    {
        "name": "EtherNetIP",                   # EtherNet/IP encapsulation header
        "fields": [
            {"name": "command", "type": "u16le"},
            {"name": "length", "type": "u16le"},
            {"name": "session_handle", "type": "u32le"},
            {"name": "status", "type": "u32le"},
            {"name": "sender_context", "type": "bytes", "size": 8},
            {"name": "options", "type": "u32le"},
            {"name": "data", "type": "rest"},
        ],
        "bind": {"over": "TCP", "ports": [44818]},
    },
    {
        "name": "TPKT",                         # TPKT (carries COTP + S7comm on 102)
        "fields": [
            {"name": "version", "type": "u8"},  # 0x03
            {"name": "reserved", "type": "u8"},
            {"name": "length", "type": "u16"},
            {"name": "cotp", "type": "rest"},
        ],
        "bind": {"over": "TCP", "ports": [102]},
    },
]

_LOADED = False


def load_builtins(register_scapy: bool = True) -> list[str]:
    """Define + register every built-in protocol. Idempotent. Returns the names.

    Each spec is registered both as a Scapy layer (via custom_proto, for the tree
    view / rules / builder) and as a SpecDissector (in the dissect registry).
    """
    global _LOADED
    from reforge.dissect import base
    from reforge.dissect.specdissector import SpecDissector

    names: list[str] = []
    for spec in BUILTIN_SPECS:
        names.append(spec["name"])
        base.register(SpecDissector(spec))     # dissect-registry path (always)

    # Scapy binding is global + one-shot; only latch _LOADED when it actually ran,
    # so a register_scapy=False call doesn't block a later real load.
    if register_scapy and not _LOADED:
        from reforge.craft.custom_proto import define_protocol
        for spec in BUILTIN_SPECS:
            try:
                define_protocol(spec, register=True)
            except Exception:
                log.warning("scapy layer for %s failed to bind", spec["name"],
                            exc_info=True)
        _LOADED = True
    return names
