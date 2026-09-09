"""Built-in ICS/OT custom dissectors (§2.8): spec dissector + registry + Scapy
binding + end-to-end dissection of real protocol bytes."""

from __future__ import annotations

import struct

from reforge.dissect import base
from reforge.dissect.builtins import BUILTIN_SPECS, load_builtins
from reforge.dissect.specdissector import SpecDissector


# --- SpecDissector: dissect + rebuild round-trip ----------------------------
def test_spec_dissector_modbus_roundtrip():
    spec = next(s for s in BUILTIN_SPECS if s["name"] == "ModbusTCP")
    d = SpecDissector(spec)
    # MBAP: txid=1, proto=0, len=6, unit=17(0x11), func=3(read holding regs) + data
    raw = struct.pack(">HHHBB", 1, 0, 6, 0x11, 3) + b"\x00\x6b\x00\x03"
    layer = d.dissect(raw)
    fields = {f.name: f.value for f in layer.fields}
    assert fields["transaction_id"] == 1 and fields["unit_id"] == 0x11
    assert fields["function_code"] == 3 and fields["data"] == b"\x00\x6b\x00\x03"
    # offsets are accurate
    off = {f.name: f.offset for f in layer.fields}
    assert off["function_code"] == 7 and off["data"] == 8
    # rebuild reproduces the original bytes
    assert d.build(layer) == raw


def test_spec_dissector_edit_and_rebuild():
    spec = next(s for s in BUILTIN_SPECS if s["name"] == "ModbusTCP")
    d = SpecDissector(spec)
    raw = struct.pack(">HHHBB", 1, 0, 6, 0x11, 3) + b"xy"
    layer = d.dissect(raw)
    # flip the function code to 6 (write single register)
    for f in layer.fields:
        if f.name == "function_code":
            f.value = 6
    rebuilt = d.build(layer)
    assert d.dissect(rebuilt).fields[4].value == 6
    assert rebuilt[7] == 6


def test_dnp3_little_endian_addresses():
    spec = next(s for s in BUILTIN_SPECS if s["name"] == "DNP3")
    d = SpecDissector(spec)
    raw = (b"\x05\x64"              # start 0x0564 big-endian per our u16 spec
           + b"\x05" + b"\xc4"      # length, control
           + struct.pack("<H", 4) + struct.pack("<H", 1)  # dest, src little-endian
           + b"payload")
    layer = d.dissect(raw)
    fields = {f.name: f.value for f in layer.fields}
    assert fields["destination"] == 4 and fields["source"] == 1   # decoded LE
    assert d.build(layer) == raw


def test_can_dissect_by_port():
    d = SpecDissector(next(s for s in BUILTIN_SPECS if s["name"] == "ModbusTCP"))
    assert d.can_dissect(b"", {"dport": 502}) is True
    assert d.can_dissect(b"", {"sport": 502}) is True     # both directions
    assert d.can_dissect(b"", {"dport": 80}) is False


# --- registry population ----------------------------------------------------
def test_load_builtins_populates_dissect_registry():
    names = load_builtins(register_scapy=False)
    reg = base.registered()
    for n in ("ModbusTCP", "DNP3", "BACnetIP", "IEC104", "EtherNetIP", "TPKT"):
        assert n in names and n in reg
        assert isinstance(reg[n], SpecDissector)


# --- Scapy binding: real end-to-end dissection ------------------------------
def test_scapy_layer_dissects_modbus_on_502():
    load_builtins(register_scapy=True)
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    mbap = struct.pack(">HHHBB", 7, 0, 6, 0x11, 3) + b"\x00\x6b\x00\x03"
    pkt = Ether() / IP() / TCP(sport=1024, dport=502) / mbap
    reparsed = Ether(bytes(pkt))
    assert reparsed.haslayer("ModbusTCP")
    m = reparsed.getlayer("ModbusTCP")
    assert int(m.transaction_id) == 7 and int(m.function_code) == 3


def test_scapy_layer_dissects_response_direction():
    load_builtins(register_scapy=True)
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    # response: sport=502 -> must also dissect (both-direction bind)
    mbap = struct.pack(">HHHBB", 7, 0, 5, 0x11, 3) + b"\x02\x00\x00"
    pkt = Ether() / IP() / TCP(sport=502, dport=1024) / mbap
    assert Ether(bytes(pkt)).haslayer("ModbusTCP")
