"""Built-in scenario steps + registry.

A step is a callable ``fn(ctx, params)`` registered by name, tagged with whether
it needs root and its MITRE ATT&CK technique. Attack/scan steps are skipped in
dry-run; inspection steps (analyze_pcap, note, sleep) always run.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

from reforge.scenario.context import ScenarioContext


@dataclass
class Step:
    fn: Callable
    needs_root: bool = False
    attack: str | None = None


STEPS: dict[str, Step] = {}


def step(name: str, needs_root: bool = False, attack: str | None = None):
    def deco(fn):
        STEPS[name] = Step(fn, needs_root, attack)
        return fn
    return deco


# ---- inspection (offline-safe) ---------------------------------------------
@step("note")
def s_note(ctx: ScenarioContext, p: dict) -> None:
    ctx.notes.append(p.get("text", ""))
    ctx.event("note", p.get("text", ""))


@step("sleep")
def s_sleep(ctx: ScenarioContext, p: dict) -> None:
    secs = float(p.get("seconds", 0))
    time.sleep(secs)
    ctx.event("sleep", f"{secs}s")


@step("analyze_pcap", attack="T1040")
def s_analyze_pcap(ctx: ScenarioContext, p: dict) -> None:
    from scapy.layers.l2 import Ether

    from reforge.attacks.creds import CredentialExtractor
    from reforge.attacks.stream_harvester import StreamHarvester
    from reforge.core.pcaputil import read_frames

    harvester = StreamHarvester()          # multi-segment TCP
    perpkt = CredentialExtractor()         # single-packet + non-TCP (SNMP)
    seen: set = set()
    n = 0
    for raw in read_frames(p["file"]):
        n += 1
        try:
            eth = Ether(raw)
        except Exception:
            continue
        creds = []
        try:
            creds += perpkt.extract(eth)
        except Exception:
            pass
        try:
            creds += harvester.add_frame(raw)
        except Exception:
            pass
        for c in creds:
            sig = (c.kind, c.username, c.secret, c.src, c.dst)
            if sig not in seen:
                seen.add(sig)
                ctx.creds.append(c)
        try:
            ctx.inventory.observe(eth)
        except Exception:
            pass
    ctx.event("analyze_pcap", f"{p['file']} ({n} pkts, {len(seen)} creds)")


@step("detect_covert", attack="T1048")
def s_detect_covert(ctx: ScenarioContext, p: dict) -> None:
    from reforge.core.pcaputil import read_packets
    from reforge.covert.detect import detect

    findings = detect(read_packets(p["file"]))
    for f in findings:
        ctx.notes.append(f"covert: {f.channel} — {f.detail} ({f.confidence})")
    ctx.event("detect_covert", f"{len(findings)} finding(s)")


@step("scan", attack="T1046")
def s_scan(ctx: ScenarioContext, p: dict) -> None:
    if ctx.dry_run:
        ctx.event("scan", f"(dry-run) {p.get('target')}")
        return
    from reforge.scan.engine import ScanEngine
    from reforge.scan.targets import expand_targets, parse_ports
    from reforge.scan.tcp import ConnectScanner, SynScanner, default_prober

    targets = expand_targets(p["target"])
    ports = parse_ports(p.get("ports", "22,80,443,445,3389,8080"))
    mode = p.get("mode", "connect")
    scanner = (ConnectScanner(float(p.get("timeout", 1.0))) if mode == "connect"
               else SynScanner(default_prober()))
    results = ScanEngine(ctx.inventory).scan_ports(targets, ports, scanner,
                                                   banners=p.get("banners", False))
    ctx.scans.update(results)
    ctx.event("scan", f"{p['target']} ports={len(ports)} mode={mode}")


# ---- active attacks (need root; started as background) ----------------------
@step("arp_spoof", needs_root=True, attack="T1557.002")
def s_arp(ctx, p):
    from reforge.attacks.arp_spoof import ArpSpoofer

    r = ArpSpoofer(p["iface"], p["victim"], p["gateway"])
    r.start(); ctx.add_background(r)
    ctx.event("arp_spoof", f"{p['victim']} <-> {p['gateway']}")


@step("dns_spoof", needs_root=True, attack="T1557")
def s_dns(ctx, p):
    from reforge.attacks.dns_spoof import DnsSpoofer

    r = DnsSpoofer(p["iface"], p.get("hostmap", {})); r.start(); ctx.add_background(r)
    ctx.event("dns_spoof", f"{len(p.get('hostmap', {}))} mappings")


@step("name_poison", needs_root=True, attack="T1557.001")
def s_name(ctx, p):
    from reforge.attacks.namepoison import NamePoisoner

    r = NamePoisoner(p["iface"], p["our_ip"]); r.start(); ctx.add_background(r)
    ctx.event("name_poison", p["our_ip"])


@step("dhcp_rogue", needs_root=True, attack="T1557")
def s_dhcp(ctx, p):
    from reforge.attacks.dhcp import RogueDhcp

    r = RogueDhcp(p["iface"], p["server"], gateway=p.get("gateway"), dns=p.get("dns"))
    r.start(); ctx.add_background(r)
    ctx.event("dhcp_rogue", p["server"])


@step("ndp_spoof", needs_root=True, attack="T1557")
def s_ndp(ctx, p):
    from reforge.attacks.ndp import NdpSpoofer

    r = NdpSpoofer(p["iface"], p["target"], p["victim"], p["our_mac"])
    r.start(); ctx.add_background(r)
    ctx.event("ndp_spoof", f"{p['target']} -> {p['our_mac']}")


@step("rogue_router", needs_root=True, attack="T1557")
def s_rogue_router(ctx, p):
    from reforge.attacks.ndp import RogueRouter

    r = RogueRouter(p["iface"], p["our_mac"], prefix=p.get("prefix", "2001:db8:dead::"))
    r.start(); ctx.add_background(r)
    ctx.event("rogue_router", f"advertising {r.prefix} as default IPv6 router")


@step("ra_flood", needs_root=True, attack="T1498")
def s_ra_flood(ctx, p):
    from reforge.attacks.ndp import RaFlood

    r = RaFlood(p["iface"], rate=p.get("rate", 400), batch=p.get("batch", 50))
    r.start(); ctx.add_background(r)
    ctx.event("ra_flood", f"flooding rogue RAs on {p['iface']}")


@step("tls_intercept", needs_root=True, attack="T1557")
def s_tls(ctx, p):
    from reforge.attacks.tls_proxy import TlsInterceptor

    r = TlsInterceptor(listen=("0.0.0.0", int(p.get("port", 8443))))
    r.start(); ctx.add_background(r)
    ctx.event("tls_intercept", f"port {p.get('port', 8443)}")
