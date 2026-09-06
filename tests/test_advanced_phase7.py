"""Phase 7: custom protocols, fuzzing, plugins, TCP seq/ack fix-ups."""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from reforge.core.apply import apply_engine
from reforge.core.packet import Packet
from reforge.core.tcpflow import TcpSeqFixer
from reforge.craft import builder, fuzz
from reforge.rules.base import Rule
from reforge.rules import matchers as M
from reforge.rules import spec as S
from reforge.rules.engine import RuleEngine


# ---- custom protocol -------------------------------------------------------
def test_define_and_use_custom_protocol():
    from reforge.craft.custom_proto import define_protocol

    spec = {
        "name": "MyProto",
        "fields": [
            {"name": "opcode", "type": "u8", "default": 1},
            {"name": "length", "type": "u16"},
            {"name": "token", "type": "bytes", "size": 4},
        ],
        "bind": {"over": "UDP", "dport": 9999},
    }
    cls = define_protocol(spec)
    # available in the builder now
    assert "MyProto" in builder.available_layers()

    # build a packet using it and dissect back
    craft = {"layers": [
        {"layer": "IP", "fields": {"dst": "10.0.0.1"}},
        {"layer": "UDP", "fields": {"dport": 9999}},
        {"layer": "MyProto", "fields": {"opcode": 7, "token": "ABCD"}},
    ]}
    data = builder.spec_to_bytes(craft)
    pkt = IP(data)
    assert pkt.haslayer("MyProto")          # auto-dissected via the UDP bind
    assert pkt["MyProto"].opcode == 7


def test_custom_protocol_field_rule():
    from reforge.craft.custom_proto import define_protocol

    define_protocol({"name": "Widget",
                     "fields": [{"name": "kind", "type": "u8"}],
                     "bind": {"over": "UDP", "dport": 8100}})
    raw = bytes(Ether() / IP(dst="10.0.0.1") / UDP(dport=8100) / b"\x05")
    pkt = Packet.from_bytes(raw)
    assert M.FieldMatch("Widget", "kind", "eq", 5).matches(pkt)


# ---- fuzzing ---------------------------------------------------------------
def test_mutate_is_deterministic_and_length_preserving():
    data = b"A" * 32
    m1 = fuzz.mutate(data, mutations=5, seed=123)
    m2 = fuzz.mutate(data, mutations=5, seed=123)
    assert m1 == m2 and m1 != data
    assert len(m1) == len(data)


def test_fuzz_action_mutates_payload():
    engine = RuleEngine([Rule("f", M.AllMatch(),
                              [S.build_action({"type": "fuzz", "mutations": 4, "seed": 7})])])
    raw = bytes(Ether() / IP(dst="10.0.0.1") / UDP(dport=1) / (b"PAYLOAD-DATA"))
    res = apply_engine(engine, raw)
    assert res.modified
    from scapy.packet import Raw
    assert Ether(res.out)[Raw].load != b"PAYLOAD-DATA"
    assert len(Ether(res.out)[Raw].load) == len(b"PAYLOAD-DATA")


# ---- plugins ---------------------------------------------------------------
PLUGIN_SRC = '''
def _set_dport_one(pkt):
    from scapy.layers.inet import TCP
    if pkt.haslayer(TCP):
        pkt[TCP].dport = 1

def register(api):
    api.register_transform("dport1", _set_dport_one)
'''


def test_plugin_loads_and_runs_as_action(tmp_path):
    from reforge.plugins import PluginManager

    pf = tmp_path / "myplugin.py"
    pf.write_text(PLUGIN_SRC)
    mgr = PluginManager()
    assert mgr.load_file(pf)

    engine = RuleEngine([Rule("p", M.AllMatch(),
                              [S.build_action({"type": "plugin", "name": "dport1"})])])
    raw = bytes(Ether() / IP(dst="10.0.0.1") / TCP(dport=80))
    res = apply_engine(engine, raw)
    assert Ether(res.out)[TCP].dport == 1


# ---- TCP seq/ack fix-ups ---------------------------------------------------
def test_seq_ack_fixups_after_length_change():
    fixer = TcpSeqFixer()

    # Forward segment #1: we grow its payload by +5 bytes.
    a1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=2000, seq=1000)
    fixer.note_length_change(a1, +5)

    # Forward segment #2 (same direction) originally seq=1010 -> must become 1015.
    a2 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000, dport=2000, seq=1010)
    assert fixer.apply(a2)
    assert a2[TCP].seq == 1015

    # Reverse segment acking our data: ack=1010 -> must become 1015.
    b1 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=2000, dport=1000, ack=1010)
    assert fixer.apply(b1)
    assert b1[TCP].ack == 1015


def test_seq_fixer_wraps_32bit():
    fixer = TcpSeqFixer()
    a1 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, seq=0)
    fixer.note_length_change(a1, +10)
    a2 = IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=2, seq=0xFFFFFFFF)
    fixer.apply(a2)
    assert a2[TCP].seq == 9  # (0xFFFFFFFF + 10) & 0xFFFFFFFF
