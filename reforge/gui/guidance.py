"""Shared in-app guidance: per-section copy, an intro strip, and the Guide data.

One source of truth for 'what is this and how do I start', used two ways:
- PanelIntro renders a compact strip at the top of each tab/panel (blurb + first
  steps + a Guide link).
- GuidePanel renders the same SECTIONS as a full reference.

Keeping the copy here means the intro strips and the Guide never drift apart.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

# ---- section copy ----------------------------------------------------------
# key: (title, blurb, steps[], when, tips[])
SECTIONS: list[dict] = [
    {
        "key": "capture",
        "title": "Capture",
        "blurb": "Watch traffic live or open a pcap; click a packet to see every layer and byte.",
        "steps": ["Pick an interface and press Start (or Open pcap)",
                  "Select a row to inspect the protocol tree + hex",
                  "Use BPF (e.g. tcp port 80) to narrow what is captured"],
        "when": "Passive visibility. The starting point for most work — capture first, then act.",
        "tips": ["BPF is tcpdump syntax and filters at capture time (kernel).",
                 "Export pcap saves what you have captured; Clear empties the list."],
    },
    {
        "key": "bridge",
        "title": "Bridge (inline)",
        "blurb": "Go inline between two NICs to edit, drop, delay, or inject live traffic.",
        "steps": ["Toolbar Mode -> Bridge, choose two interfaces",
                  "Press Arm to enable edits (unarmed = safe pass-through), then Start",
                  "Rules and the Intercept tab now act on the live stream"],
        "when": "Active, transparent man-in-the-middle on a wire you sit in the middle of.",
        "tips": ["Unarmed forwards everything untouched — arm only when ready.",
                 "TCP seq-fix keeps flows in sync after length-changing edits.",
                 "Kill-switch releases everything held and stops editing immediately."],
    },
    {
        "key": "intercept",
        "title": "Intercept",
        "blurb": "Catch matching traffic, edit it (hex or ASCII), and forward only the change.",
        "steps": ["Tick Intercept and set a catch filter (or pick a preset)",
                  "Select a held item, edit it, press Forward modified (or Drop)",
                  "Apply to all promotes your edit to every match — and resends"],
        "when": "Interactive MITM: grab a specific packet/message, change it, let it go.",
        "tips": ["Hold-limit + auto-release stop a busy stream from drowning the queue.",
                 "HTTP flows can hold whole messages, not packets (Attacks -> TCP proxy).",
                 "Filter syntax is below; 'Apply to all' is how you edit a whole stream."],
    },
    {
        "key": "rules",
        "title": "Rules",
        "blurb": "Automatic match -> action rewrites applied inline at line rate.",
        "steps": ["Add a rule: a match (e.g. TCP.dport == 80) and actions",
                  "Actions: set field, replace payload, drop, delay, duplicate, hold",
                  "Rules run in order on every packet the bridge forwards"],
        "when": "Hands-off, high-volume changes — the opposite of interactive intercept.",
        "tips": ["Dry-run evaluates a ruleset over captured packets without editing.",
                 "A Hold action sends matches to the Intercept tab for manual edit."],
    },
    {
        "key": "builder",
        "title": "Builder",
        "blurb": "Craft any packet from a layer palette, edit every field, and transmit.",
        "steps": ["Add layers (Ether/IP/TCP/...), edit fields in the table",
                  "Send, Send & Receive, or Fuzz send on an interface",
                  "Load from capture to edit-and-resend a real packet"],
        "when": "Build probes and payloads by hand, or replay/modify a captured frame.",
        "tips": ["Load protocol adds a custom protocol to the palette.",
                 "Evade send applies an IDS-evasion technique to the frame."],
    },
    {
        "key": "fuzzing",
        "title": "Fuzzing",
        "blurb": "Mutation and smart, structure-aware fuzzing of a packet template.",
        "steps": ["Provide/seed a template packet", "Choose a strategy and count",
                  "Run — mutated variants are generated (and optionally sent)"],
        "when": "Stress a parser or find edge cases from a known-good packet.",
        "tips": ["Smart fuzzing targets fields/lengths rather than random bytes."],
    },
    {
        "key": "attacks",
        "title": "Attacks",
        "blurb": "Active MITM toolkit: ARP/NDP, DHCP, DNS, TLS intercept, HTTP proxy, creds.",
        "steps": ["Pick a technique box, fill its fields, press Start",
                  "TCP proxy / TLS interceptor rewrite HTTP (and hold messages)",
                  "Stop ends the technique; watch the status line under each box"],
        "when": "Position yourself in the path and manipulate application traffic.",
        "tips": ["TLS interception needs its CA installed on the target.",
                 "TCP proxy -> Interactive intercept holds whole HTTP messages."],
    },
    {
        "key": "scan",
        "title": "Scan",
        "blurb": "Discover live hosts and open ports; feed results into Recon.",
        "steps": ["Enter targets (10.0.0.0/24, a-b ranges, lists) and ports",
                  "Run a SYN or connect scan; optionally grab banners",
                  "Open ports and services land in the asset inventory"],
        "when": "Map a segment before deciding where to sit inline or attack.",
        "tips": ["Targets accept CIDR, ranges (10.0.0.5-9), and comma lists."],
    },
    {
        "key": "recon",
        "title": "Recon",
        "blurb": "Passive asset inventory built from everything observed.",
        "steps": ["Just capture or bridge — hosts, OS guesses, services accrue",
                  "Review the inventory; it merges scan + sniffed data"],
        "when": "Build a picture of the environment without sending a packet.",
        "tips": ["Sensors and scans both feed the same inventory."],
    },
    {
        "key": "creds",
        "title": "Creds",
        "blurb": "Credentials extracted from observed and relayed traffic.",
        "steps": ["Capture/bridge/proxy traffic that carries auth",
                  "Harvested credentials appear here with source context"],
        "when": "Collect basic-auth, form logins, and protocol creds seen in flight.",
        "tips": ["Route HTTPS through the TLS interceptor to see TLS-wrapped creds."],
    },
    {
        "key": "scenario",
        "title": "Scenario",
        "blurb": "Script multi-step engagements via the automation API and report.",
        "steps": ["Load or write a scenario of ordered steps", "Run it",
                  "Review the generated report of what happened"],
        "when": "Repeatable, auditable runs instead of manual clicking.",
        "tips": ["Steps map to the same capabilities the GUI exposes."],
    },
    {
        "key": "console",
        "title": "Console",
        "blurb": "Distributed multi-sensor collector — merge many sensors into one view.",
        "steps": ["Start the collector (mTLS)", "Point sensors at it",
                  "Watch merged hosts, creds, and events arrive"],
        "when": "Cover several segments at once from one operator console.",
        "tips": ["Transport is mutually authenticated (mTLS); keep it on a trusted path."],
    },
    {
        "key": "diagnostics",
        "title": "Diagnostics",
        "blurb": "Live health, self-tests, and a troubleshooting bundle you can export.",
        "steps": ["Watch pipeline counters and health while running",
                  "Run Doctor for self-checks", "Export a bundle if something is off"],
        "when": "Confirm the tool is healthy, or gather evidence when it is not.",
        "tips": ["Counters here read the same pipeline the bridge drives."],
    },
    {
        "key": "vault",
        "title": "Vault",
        "blurb": "Encrypt or decrypt an engagement artifact at rest (AES-256-GCM).",
        "steps": ["Toolbar Vault", "Choose a file and passphrase", "Encrypt or decrypt"],
        "when": "Protect captures, creds, and reports on an airgapped host.",
        "tips": ["Keys are derived with scrypt; the passphrase is never stored."],
    },
]

SECTION_BY_KEY = {s["key"]: s for s in SECTIONS}

FILTER_HELP = {
    "title": "Filter syntax (Intercept catch filter and Apply-to-all scope)",
    "grammar": "LAYER.field OP value   —   combine with and / or / not and ( )",
    "ops": "OP:  ==  !=  <  <=  >  >=  in  contains  cidr",
    "examples": [
        'TCP.dport == 80',
        'IP.src cidr 10.0.0.0/24 and TCP.dport == 80',
        'Raw.load contains "login" or Raw.load contains "password"',
        'TCP.dport in [80, 443, 8080]',
        'DNS and not IP.src == 10.0.0.1',
    ],
    "note": "Values: numbers (80 or 0x50), quoted strings, lists [a, b], addresses/CIDRs. "
            "A bare layer name (e.g. UDP) matches any packet with that layer. "
            "BPF in the capture toolbar is separate — that is tcpdump syntax, applied at "
            "capture time.",
}


def bpf_help_tooltip() -> str:
    ex = ["tcp port 80", "host 10.0.0.5", "net 10.0.0.0/24", "udp port 53",
          "arp or icmp", "tcp and not port 22"]
    body = "<br>".join(f"&nbsp;&nbsp;<code>{x}</code>" for x in ex)
    return ("<b>Capture filter (BPF / tcpdump syntax)</b><br>"
            "Applied in the kernel at capture time to limit what is captured.<br><br>"
            f"{body}<br><br><i>Different from the Intercept filter, which selects packets "
            "to hold and edit once captured.</i>")


def filter_help_tooltip() -> str:
    e = "<br>".join(f"&nbsp;&nbsp;<code>{x}</code>" for x in FILTER_HELP["examples"])
    return (f"<b>{FILTER_HELP['title']}</b><br>{FILTER_HELP['grammar']}<br>"
            f"{FILTER_HELP['ops']}<br><br>{e}<br><br>"
            f"<i>{FILTER_HELP['note']}</i>")


# ---- intro strip -----------------------------------------------------------
class PanelIntro(QFrame):
    """Compact 'what this does + first steps' header for a panel."""

    def __init__(self, section_key: str, on_guide=None, parent=None):
        super().__init__(parent)
        sec = SECTION_BY_KEY.get(section_key, {})
        self.setObjectName("panelIntro")
        self.setStyleSheet(
            "#panelIntro{background:palette(alternate-base);border:1px solid palette(midlight);"
            "border-radius:6px;} #panelIntro QLabel{color:palette(text);}")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 7, 10, 7)
        outer.setSpacing(2)

        top = QHBoxLayout(); top.setSpacing(8)
        blurb = QLabel(sec.get("blurb", ""))
        blurb.setWordWrap(True)
        blurb.setStyleSheet("font-weight:600;")
        top.addWidget(blurb, 1)
        if on_guide is not None:
            btn = QPushButton("Guide ›")
            btn.setFlat(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet("QPushButton{color:palette(link);border:none;font-weight:600;}")
            btn.clicked.connect(lambda: on_guide(section_key))
            top.addWidget(btn, 0, Qt.AlignTop)
        outer.addLayout(top)

        steps = sec.get("steps", [])
        if steps:
            line = "   ".join(f"{i}. {s}" for i, s in enumerate(steps, 1))
            lbl = QLabel(line)
            lbl.setWordWrap(True)
            lbl.setStyleSheet("color:palette(mid);")
            outer.addWidget(lbl)


def wrap_with_intro(panel: QWidget, section_key: str, on_guide=None) -> QWidget:
    """Return a container with a PanelIntro above the given panel."""
    container = QWidget()
    lay = QVBoxLayout(container)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    lay.addWidget(PanelIntro(section_key, on_guide))
    lay.addWidget(panel, 1)
    return container
