"""Packet crafting — build a layer stack from a spec, and dissect back to a spec.

A craft spec is JSON-friendly so it can be saved as a template or in a session:

    {"layers": [
        {"layer": "Ether", "fields": {"dst": "ff:ff:ff:ff:ff:ff"}},
        {"layer": "IP",    "fields": {"dst": "10.0.0.1"}},
        {"layer": "UDP",   "fields": {"dport": 53}},
        {"layer": "Raw",   "fields": {"load": "hello"}}
    ]}

Every header and data field is editable. Checksums/lengths are left unset so
Scapy computes them on build (the operator can override any field explicitly).
"""

from __future__ import annotations

from typing import Any

# Layers the builder offers, name -> lazy import path. Kept as strings so the
# module imports cheaply; classes are resolved on demand.
_LAYER_PATHS = {
    "Ether": ("scapy.layers.l2", "Ether"),
    "Dot1Q": ("scapy.layers.l2", "Dot1Q"),
    "ARP": ("scapy.layers.l2", "ARP"),
    "IP": ("scapy.layers.inet", "IP"),
    "IPv6": ("scapy.layers.inet6", "IPv6"),
    "ICMP": ("scapy.layers.inet", "ICMP"),
    "TCP": ("scapy.layers.inet", "TCP"),
    "UDP": ("scapy.layers.inet", "UDP"),
    "DNS": ("scapy.layers.dns", "DNS"),
    "Raw": ("scapy.packet", "Raw"),
}

# Fields Scapy should recompute rather than take from a captured packet.
_AUTO = {"len", "chksum", "plen", "ulen"}


def available_layers() -> list[str]:
    return list(_LAYER_PATHS)


def _layer_class(name: str):
    mod, cls = _LAYER_PATHS[name]
    return getattr(__import__(mod, fromlist=[cls]), cls)


def layer_fields(name: str) -> list[tuple[str, str]]:
    """Return (field_name, default_repr) for a layer, for building GUI forms."""
    cls = _layer_class(name)
    inst = cls()
    out = []
    for fdesc in inst.fields_desc:
        try:
            out.append((fdesc.name, fdesc.i2repr(inst, inst.getfieldval(fdesc.name))))
        except Exception:
            out.append((fdesc.name, ""))
    return out


def _coerce(cls, field: str, value: Any):
    """Coerce a spec/GUI value toward the field's type."""
    if field == "load":
        if isinstance(value, bytes):
            return value
        s = str(value)
        if s.startswith("0x"):
            try:
                return bytes.fromhex(s[2:])
            except ValueError:
                return s.encode()
        return s.encode()
    if isinstance(value, str):
        # numeric field given as text -> int
        try:
            default = cls().getfieldval(field)
        except Exception:
            default = None
        if isinstance(default, int):
            try:
                return int(value, 0)
            except ValueError:
                return value
    return value


def build_layer(name: str, fields: dict) -> Any:
    cls = _layer_class(name)
    layer = cls()
    for fname, val in (fields or {}).items():
        try:
            setattr(layer, fname, _coerce(cls, fname, val))
        except Exception:
            pass
    return layer


def build_packet(spec: dict) -> Any:
    """Build a Scapy packet from a craft spec."""
    layers = spec.get("layers", [])
    if not layers:
        from scapy.layers.l2 import Ether

        return Ether()
    built = [build_layer(ld["layer"], ld.get("fields", {})) for ld in layers]
    pkt = built[0]
    for layer in built[1:]:
        pkt = pkt / layer
    return pkt


def spec_to_bytes(spec: dict) -> bytes:
    return bytes(build_packet(spec))


def _jsonify(val: Any) -> Any:
    if isinstance(val, bool) or isinstance(val, int) or isinstance(val, str):
        return val
    if isinstance(val, bytes):
        return "0x" + val.hex()
    return str(val)


def packet_to_spec(pkt: Any) -> dict:
    """Dissect a Scapy packet into an editable craft spec (edit-and-resend).

    Only explicitly-set fields are captured, and auto fields (len/checksum) are
    dropped so they recompute on rebuild.
    """
    layers: list[dict] = []
    layer = pkt
    known = set(_LAYER_PATHS)
    while layer is not None and layer.__class__.__name__ != "NoPayload":
        name = layer.__class__.__name__
        if name in known:
            fields = {}
            for k, v in layer.fields.items():
                if k in _AUTO or v is None:
                    continue
                # Skip container-typed fields (e.g. TCP/IP options) — they don't
                # round-trip as text; they default on rebuild.
                if isinstance(v, (list, tuple, dict, set)):
                    continue
                fields[k] = _jsonify(v)
            layers.append({"layer": name, "fields": fields})
        layer = layer.payload if getattr(layer, "payload", None) is not None else None
    return {"layers": layers}


def bytes_to_spec(data: bytes, link: str = "ether") -> dict:
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    if link == "ip":
        base = IPv6 if (data and (data[0] >> 4) == 6) else IP
    else:
        base = Ether
    return packet_to_spec(base(data))
