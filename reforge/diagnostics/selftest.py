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

    # --- interactive intercept: a match is held, then edited and forwarded ---
    from reforge.core.intercept import InterceptQueue

    iq = InterceptQueue()
    hold_engine = RuleEngine([Rule("selftest-hold",
                                   M.FieldMatch("UDP", "dport", "eq", 40404), [A.Hold()])])
    ibridge = UserspaceBridge("selfA", "selfB", hold_engine, intercept=iq)
    iout: list[bytes] = []
    ibridge._forward("selfA", marker, iout.append)
    held_ok = iq.count() == 1 and iout == []          # held, nothing forwarded yet
    steps.append(SelfTestStep("intercept holds a match", held_ok, f"held={iq.count()}"))

    edit_ok = False
    if held_ok:
        edited = marker.replace(b"REFORGE-SELFTEST", b"REFORGE-EDITED!!")   # same length
        iq.resolve(iq.pending()[0].id, "modify", edited)
        edit_ok = len(iout) == 1 and b"REFORGE-EDITED" in iout[0]
    steps.append(SelfTestStep("intercept edit forwards", edit_ok))

    # --- HTTP message framing + body rewrite (the message-intercept path) ---
    from reforge.attacks.http_relay import apply_transforms
    from reforge.core.httpframer import HttpFramer

    req = b"POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 10\r\n\r\nuser=admin"
    framer = HttpFramer()
    framed = list(framer.feed(req))
    frame_ok = len(framed) == 1 and framed[0] == req
    steps.append(SelfTestStep("HTTP message framed", frame_ok, f"{len(framed)} message(s)"))

    def _rewrite(msg, from_client):
        if b"admin" in msg.body:
            msg.body = msg.body.replace(b"admin", b"guest")     # same length
            return True
        return False

    rewritten = apply_transforms(req, True, [_rewrite])
    body_ok = b"user=guest" in rewritten and b"admin" not in rewritten
    steps.append(SelfTestStep("HTTP body rewrite", body_ok))

    return SelfTestReport(ok=all(s.ok for s in steps), steps=steps)
