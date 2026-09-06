"""End-to-end pipeline self-test.

Injects a known marker frame through the bridge forwarding path with a rule that
rewrites a field, and confirms it traverses capture → rules → modify → egress
and comes out changed as expected. Validates the whole chain in milliseconds,
before an engagement, without touching a real NIC.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SelfTestStep:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class SelfTestReport:
    ok: bool
    steps: list[SelfTestStep] = field(default_factory=list)


def run_selftest() -> SelfTestReport:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether

    from reforge.core.bridge import UserspaceBridge
    from reforge.rules import actions as A
    from reforge.rules import matchers as M
    from reforge.rules.base import Rule
    from reforge.rules.engine import RuleEngine

    steps: list[SelfTestStep] = []

    marker = bytes(Ether() / IP(src="10.255.0.1", dst="10.255.0.2") / UDP(dport=40404) / b"REFORGE-SELFTEST")
    steps.append(SelfTestStep("build marker frame", True, f"{len(marker)} bytes"))

    engine = RuleEngine([Rule("selftest-rewrite", M.FieldMatch("UDP", "dport", "eq", 40404),
                              [A.SetField("IP", "dst", "10.255.0.9")])])
    bridge = UserspaceBridge("selfA", "selfB", engine)

    sent: list[bytes] = []
    bridge._forward("selfA", marker, sent.append)

    fwd_ok = len(sent) == 1
    steps.append(SelfTestStep("frame traverses pipeline", fwd_ok,
                              f"{len(sent)} frame(s) forwarded"))

    modified_ok = False
    dst_ok = False
    if fwd_ok:
        modified_ok = bridge.counters.modified == 1
        try:
            dst_ok = Ether(sent[0])[IP].dst == "10.255.0.9"
        except Exception:
            dst_ok = False
    steps.append(SelfTestStep("rule modified the frame", modified_ok,
                              f"modified={bridge.counters.modified}"))
    steps.append(SelfTestStep("field rewrite applied", dst_ok,
                              "IP.dst == 10.255.0.9" if dst_ok else "rewrite not seen"))

    # checksum recomputed correctly on the modified frame
    csum_ok = False
    if dst_ok:
        try:
            pkt = Ether(sent[0])
            stored = pkt[IP].chksum
            del pkt[IP].chksum
            csum_ok = Ether(bytes(pkt))[IP].chksum == stored
        except Exception:
            csum_ok = False
    steps.append(SelfTestStep("checksum recomputed", csum_ok))

    return SelfTestReport(ok=all(s.ok for s in steps), steps=steps)
