"""The live engagement record — hosts, credentials, a timeline, and a report.

Aggregates findings as the operator works, persists them as JSON so they survive
across sessions, and renders a standalone HTML report (plus Markdown/JSON) that
can be handed off. Hosts and credentials are snapshotted from the live recon
inventory and credential harvest; the timeline is milestones the operator hit.
"""

from __future__ import annotations

import html
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from reforge.scenario.report import Report


@dataclass
class Event:
    t: float                  # seconds since the engagement started
    kind: str                 # short tag: capture / bridge / mitm / scan / transform ...
    detail: str = ""


@dataclass
class Engagement:
    name: str = "engagement"
    started: float = field(default_factory=time.time)
    events: list = field(default_factory=list)      # list[Event]
    notes: list = field(default_factory=list)
    hosts: list = field(default_factory=list)        # snapshot dicts
    creds: list = field(default_factory=list)        # snapshot dicts

    # ---- accumulation -------------------------------------------------------
    def log(self, kind: str, detail: str = "") -> None:
        self.events.append(Event(round(time.time() - self.started, 1), kind, detail))

    def snapshot(self, hosts: list | None = None, creds: list | None = None) -> None:
        if hosts is not None:
            self.hosts = hosts
        if creds is not None:
            self.creds = creds

    def reset(self) -> None:
        self.started = time.time()
        self.events.clear()
        self.notes.clear()
        self.hosts.clear()
        self.creds.clear()

    # ---- report -------------------------------------------------------------
    def to_report(self, techniques: list | None = None) -> Report:
        events = [{"t": e.t, "step": e.kind, "detail": e.detail} for e in self.events]
        return Report(name=self.name, hosts=self.hosts, credentials=self.creds,
                      events=events, notes=self.notes, techniques=techniques or [])

    def render_markdown(self) -> str:
        return self.to_report().to_markdown()

    def render_html(self, stats: dict | None = None) -> str:
        e = html.escape
        started = time.strftime("%Y-%m-%d %H:%M", time.localtime(self.started))
        tiles = [("Hosts", len(self.hosts)), ("Credentials", len(self.creds)),
                 ("Timeline events", len(self.events))]
        for k, v in (stats or {}).items():
            tiles.append((k, v))
        tile_html = "".join(
            f'<div class="tile"><div class="n">{e(str(v))}</div>'
            f'<div class="k">{e(str(k))}</div></div>' for k, v in tiles)

        cred_rows = "".join(
            f"<tr><td>{e(str(c.get('kind','')))}</td><td>{e(str(c.get('proto','')))}</td>"
            f"<td class=m>{e(str(c.get('src','')))}</td><td class=m>{e(str(c.get('dst','')))}</td>"
            f"<td>{e(str(c.get('username','')))}</td><td class=s>{e(str(c.get('secret','')))}</td></tr>"
            for c in self.creds) or "<tr><td colspan=6 class=empty>none</td></tr>"

        host_rows = ""
        for h in self.hosts:
            svcs = ", ".join(f"{p}:{v}" for p, v in sorted((h.get("services") or {}).items()))
            host_rows += (f"<tr><td class=m>{e(str(h.get('ip','')))}</td>"
                          f"<td class=m>{e(str(h.get('mac','')))}</td>"
                          f"<td>{e(str(h.get('os_family','')))}</td><td>{e(svcs)}</td></tr>")
        host_rows = host_rows or "<tr><td colspan=4 class=empty>none</td></tr>"

        tl = "".join(f'<li><span class=t>{e(f"{ev.t:>7.1f}s")}</span> '
                     f'<b>{e(ev.kind)}</b> {e(ev.detail)}</li>' for ev in self.events) \
            or "<li class=empty>no events</li>"

        return f"""<!doctype html><html><head><meta charset=utf-8>
<title>Reforge report — {e(self.name)}</title><style>
:root{{--bg:#0f1320;--card:#171c2b;--bd:#28303f;--tx:#e6ebf4;--mut:#8b93a7;--ac:#4d9fff;--ok:#3ddc97;--wn:#ffb454;}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--tx);
font:14px/1.5 "Inter","Segoe UI",system-ui,sans-serif;padding:32px;max-width:1000px;margin:auto}}
h1{{margin:0 0 2px;font-size:22px}}.sub{{color:var(--mut);margin-bottom:20px}}
.tiles{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.tile{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 18px;min-width:120px}}
.tile .n{{font-size:26px;font-weight:800;color:var(--ac)}}.tile .k{{color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.06em}}
h2{{font-size:15px;margin:26px 0 8px;border-bottom:1px solid var(--bd);padding-bottom:6px}}
table{{width:100%;border-collapse:collapse;font-size:13px;background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden}}
th{{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em;padding:7px 10px;border-bottom:1px solid var(--bd)}}
td{{padding:6px 10px;border-bottom:1px solid var(--bd)}}tr:last-child td{{border-bottom:none}}
.m{{font-family:ui-monospace,monospace;color:var(--mut)}}.s{{font-family:ui-monospace,monospace;color:var(--wn)}}
.empty{{color:var(--mut);text-align:center}}
ul.tl{{list-style:none;padding:0;background:var(--card);border:1px solid var(--bd);border-radius:8px}}
ul.tl li{{padding:6px 12px;border-bottom:1px solid var(--bd)}}ul.tl li:last-child{{border:none}}
.tl .t{{font-family:ui-monospace,monospace;color:var(--mut);margin-right:8px}}
footer{{color:var(--mut);margin-top:28px;font-size:12px}}
</style></head><body>
<h1>Reforge engagement report</h1>
<div class=sub>{e(self.name)} · started {started}</div>
<div class=tiles>{tile_html}</div>
<h2>Credentials</h2>
<table><tr><th>Kind</th><th>Proto</th><th>From</th><th>To</th><th>User</th><th>Secret</th></tr>{cred_rows}</table>
<h2>Hosts</h2>
<table><tr><th>IP</th><th>MAC</th><th>OS</th><th>Services</th></tr>{host_rows}</table>
<h2>Timeline</h2>
<ul class=tl>{tl}</ul>
<footer>Generated by Reforge · for authorized engagements only</footer>
</body></html>"""

    # ---- persistence --------------------------------------------------------
    def to_dict(self) -> dict:
        return {"name": self.name, "started": self.started,
                "events": [{"t": e.t, "kind": e.kind, "detail": e.detail} for e in self.events],
                "notes": self.notes, "hosts": self.hosts, "creds": self.creds}

    @classmethod
    def from_dict(cls, d: dict) -> Engagement:
        e = cls(name=d.get("name", "engagement"))
        e.started = d.get("started", time.time())
        e.events = [Event(**ev) for ev in d.get("events", [])]
        e.notes = list(d.get("notes", []))
        e.hosts = list(d.get("hosts", []))
        e.creds = list(d.get("creds", []))
        return e

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=str))

    @classmethod
    def load(cls, path: str | Path) -> Engagement:
        p = Path(path)
        if p.exists():
            try:
                return cls.from_dict(json.loads(p.read_text()))
            except Exception:
                pass
        return cls()
