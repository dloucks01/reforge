"""Engagement report built from a scenario context."""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class Report:
    name: str = "scenario"
    hosts: list = field(default_factory=list)          # asset inventory snapshot
    credentials: list = field(default_factory=list)
    scans: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    techniques: list = field(default_factory=list)     # MITRE ATT&CK IDs used

    def to_dict(self) -> dict:
        return {
            "tool": "reforge",
            "scenario": self.name,
            "summary": {
                "hosts": len(self.hosts),
                "credentials": len(self.credentials),
                "scanned_targets": len(self.scans),
                "techniques": self.techniques,
            },
            "hosts": self.hosts,
            "credentials": self.credentials,
            "scans": self.scans,
            "events": self.events,
            "notes": self.notes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_markdown(self) -> str:
        d = self.to_dict()
        s = d["summary"]
        out = [f"# Engagement report — {self.name}", ""]
        out.append(f"- Hosts discovered: **{s['hosts']}**")
        out.append(f"- Credentials harvested: **{s['credentials']}**")
        out.append(f"- Targets scanned: **{s['scanned_targets']}**")
        if self.techniques:
            out.append(f"- ATT&CK techniques: {', '.join(self.techniques)}")
        out.append("")
        if self.credentials:
            out += ["## Credentials", "", "| kind | proto | from | to | user | secret |",
                    "|---|---|---|---|---|---|"]
            for c in self.credentials:
                out.append(f"| {c.get('kind')} | {c.get('proto')} | {c.get('src')} | "
                           f"{c.get('dst')} | {c.get('username')} | {c.get('secret')} |")
            out.append("")
        if self.hosts:
            out += ["## Hosts", "", "| ip | mac | os | services |", "|---|---|---|---|"]
            for h in self.hosts:
                svcs = ", ".join(f"{p}:{v}" for p, v in sorted(h.get("services", {}).items()))
                out.append(f"| {h.get('ip')} | {h.get('mac')} | {h.get('os_family')} | {svcs} |")
            out.append("")
        if self.events:
            out += ["## Timeline", ""]
            for e in self.events:
                out.append(f"- `{e['t']:>7}s` **{e['step']}** {e['detail']}")
        return "\n".join(out)


def build_report(ctx, name: str, techniques: list | None = None) -> Report:
    hosts = []
    for h in ctx.inventory.list_hosts():
        hosts.append({"ip": h.ip, "mac": h.mac, "os_family": h.os_family,
                      "services": dict(h.services), "hostnames": sorted(h.hostnames)})
    creds = [c.as_dict() if hasattr(c, "as_dict") else dict(c) for c in ctx.creds]
    events = [{"t": e.t, "step": e.step, "detail": e.detail} for e in ctx.events]
    return Report(name=name, hosts=hosts, credentials=creds, scans=dict(ctx.scans),
                  events=events, notes=list(ctx.notes), techniques=techniques or [])
