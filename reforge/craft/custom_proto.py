"""Custom / proprietary protocol dissectors from a declarative spec.

Operators define a protocol as a list of fields; we build a real Scapy layer
class from it and (optionally) bind it under TCP/UDP on a port. Once defined the
protocol gets the same tree view, field-level rules, and builder support as any
built-in — essential for ICS/OT and proprietary traffic ("all protocols matter").

Spec (JSON-friendly, saveable in a session / importable offline):

    {
      "name": "MyProto",
      "fields": [
        {"name": "opcode", "type": "u8",  "default": 1},
        {"name": "length", "type": "u16"},
        {"name": "token",  "type": "bytes", "size": 4},
        {"name": "payload","type": "rest"}
      ],
      "bind": {"over": "UDP", "dport": 9999}
    }

Field types: u8/u16/u32/u64 (big-endian), u16le/u32le (little-endian),
i8/i16/i32 (signed), bytes (size=N fixed), str (size=N fixed), rest (remaining).
"""

from __future__ import annotations

from reforge.craft import builder


def _make_field(spec: dict):
    from scapy.fields import (
        ByteField,
        IntField,
        LEIntField,
        LEShortField,
        LongField,
        ShortField,
        SignedByteField,
        SignedIntField,
        SignedShortField,
        StrField,
        StrFixedLenField,
    )

    name = spec["name"]
    t = spec.get("type", "u8")
    default = spec.get("default")
    size = int(spec.get("size", 0) or 0)

    simple = {
        "u8": (ByteField, 0), "u16": (ShortField, 0), "u32": (IntField, 0),
        "u64": (LongField, 0), "u16le": (LEShortField, 0), "u32le": (LEIntField, 0),
        "i8": (SignedByteField, 0), "i16": (SignedShortField, 0), "i32": (SignedIntField, 0),
    }
    if t in simple:
        cls, dflt = simple[t]
        return cls(name, default if default is not None else dflt)
    if t in ("bytes", "str"):
        return StrFixedLenField(name, (default or "").encode() if isinstance(default, str)
                                else (default or b""), length=size or 1)
    if t == "rest":
        return StrField(name, (default or "").encode() if isinstance(default, str)
                        else (default or b""))
    raise ValueError(f"unknown field type: {t}")


def define_protocol(spec: dict, register: bool = True):
    """Build (and register) a Scapy layer class from a spec. Returns the class."""
    from scapy.packet import Packet, bind_layers

    name = spec["name"]
    fields = [_make_field(f) for f in spec.get("fields", [])]
    cls = type(name, (Packet,), {"name": name, "fields_desc": fields})

    bind = spec.get("bind")
    if bind:
        over = {"TCP": ("scapy.layers.inet", "TCP"),
                "UDP": ("scapy.layers.inet", "UDP")}.get(bind.get("over", "UDP"))
        if over:
            base = getattr(__import__(over[0], fromlist=[over[1]]), over[1])
            key = {}
            if "dport" in bind:
                key["dport"] = int(bind["dport"])
            if "sport" in bind:
                key["sport"] = int(bind["sport"])
            bind_layers(base, cls, **key)

    if register:
        builder.register_custom(name, cls)
    return cls
