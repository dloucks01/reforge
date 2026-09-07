"""Derive persistent rewrite actions from a single interactive edit.

The 'edit one, apply to all' path: the operator edits one held packet, and we
diff original vs edited bytes to synthesize rule actions that reproduce the same
change on every matching packet (and on any resend), so a whole stream — or
future traffic — is transformed automatically instead of packet-by-packet.

- A changed application payload becomes a PayloadReplace(old_slice -> new_slice),
  which self-scopes: it only rewrites packets that actually contain old_slice.
- A changed header field becomes a SetField(layer, field, new_value).

Returns [] when the two byte strings are identical or no change is derivable.
"""

from __future__ import annotations

from reforge.core.packet import _AUTO_FIELDS, _iter_layers
from reforge.rules.base import Action


def _dissect(raw: bytes, link: str):
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether

    if link == "ip":
        return (IPv6 if (raw and (raw[0] >> 4) == 6) else IP)(raw)
    return Ether(raw)


def _diff_middle(a: bytes, b: bytes) -> tuple[bytes, bytes] | None:
    """Strip the common prefix/suffix; return the differing middles, or None."""
    if a == b:
        return None
    p = 0
    while p < len(a) and p < len(b) and a[p] == b[p]:
        p += 1
    s = 0
    while s < (len(a) - p) and s < (len(b) - p) and a[-1 - s] == b[-1 - s]:
        s += 1
    old = a[p:len(a) - s]
    new = b[p:len(b) - s]
    if not old and not new:
        return None
    return old, new


def derive_actions(original: bytes, edited: bytes, link: str = "ether") -> list[Action]:
    """Synthesize rewrite Actions reproducing edited-from-original on any packet."""
    from scapy.packet import Padding, Raw

    from reforge.rules.actions import PayloadReplace, SetField

    if original == edited:
        return []

    actions: list[Action] = []
    try:
        o = _dissect(original, link)
        e = _dissect(edited, link)
    except Exception:
        return []

    # 1) application payload change -> self-scoping find/replace
    if o.haslayer(Raw) and e.haslayer(Raw):
        d = _diff_middle(bytes(o[Raw].load), bytes(e[Raw].load))
        if d and d[0]:                          # need a non-empty needle to match on
            actions.append(PayloadReplace(d[0], d[1]))

    # 2) header field changes -> SetField per changed field
    o_layers: dict[str, object] = {}
    for lyr in _iter_layers(o):
        o_layers.setdefault(lyr.__class__.__name__, lyr)
    for el in _iter_layers(e):
        name = el.__class__.__name__
        if name in ("Raw", "Padding", "NoPayload") or isinstance(el, (Raw, Padding)):
            continue
        ol = o_layers.get(name)
        if ol is None:
            continue
        for f in getattr(el, "fields_desc", []):
            fn = f.name
            if fn in _AUTO_FIELDS:
                continue
            try:
                ov = ol.getfieldval(fn)
                ev = el.getfieldval(fn)
            except Exception:
                continue
            if ov != ev:
                actions.append(SetField(name, fn, ev))
    return actions


def describe_actions(actions: list[Action]) -> str:
    """Short human summary of derived actions for the status line."""
    parts: list[str] = []
    for a in actions:
        cls = a.__class__.__name__
        if cls == "PayloadReplace":
            parts.append(f"payload {a.find!r}->{a.replace!r}")
        elif cls == "SetField":
            parts.append(f"{a.layer}.{a.field}={a.value!r}")
        else:
            parts.append(cls)
    return ", ".join(parts) if parts else "no change"
