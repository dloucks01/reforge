# Inline Packet Interception & Manipulation Suite — Project Plan (v2, deep)

**Codename:** (working title) *Interceptor*
**Target platform:** Linux — Kali and broader Debian family
**Form factor:** Standalone, self-contained GUI application, deployed onto an **airgapped** host
**Use context:** Authorized offensive security engagements only
**Status:** Planning / pre-implementation
**Last updated:** 2026-09-06

---

## 0. Requirements locked in this round

| Question | Decision |
|---|---|
| Link speeds | **All** — from 100 Mbps up to 100G. High-performance backends are mandatory, not optional. |
| Operators | **Single operator** — no multi-user/RBAC complexity needed. |
| Protocol coverage | **All protocols matter** — full L2–L7 including non-IP, industrial/OT, and custom/proprietary. **Unicast, multicast, and broadcast** all in scope. |
| Media | **Copper and fiber.** Fiber is supported (SFP/SFP+/QSFP NICs, optical taps). |
| Distro support | **Kali + broader Debian.** |
| Safety/authorization gating | **Dropped.** Tool is for authorized use; no legal gates, arm-nag, or scope enforcement. Functional reliability controls (fail-open watchdog, kill-switch, dry-run) are retained purely as *operational* features. |

---

## 1. Mission & scope

A stylized, responsive Linux desktop application that sits **in line** with a network link and can:

1. **Capture** traffic passing through the host in real time, at any link speed.
2. **Inspect** every layer of every packet (L2–L7) with a Wireshark-grade detail view.
3. **Manipulate** any header field or payload byte of intercepted packets and **forward the modified packet in place of the original**.
4. **Craft** new packets from scratch — every header and data field editable — and transmit them.
5. **Automate** all of the above via a match→action rule engine and a Python plugin system.
6. **Self-diagnose and be repairable by the operator** — a first-class troubleshooting subsystem (see §9).

Runs **fully offline** with no runtime network calls, telemetry, or update checks.

### Non-goals (v1)
- Not a general IDS/IPS (engine could grow into one later).
- TLS content interception (cert injection) is an optional later module (§13).
- Single host only; no distributed/multi-sensor operation in v1.

---

## 2. Interception architecture — how traffic comes under our control

Placement is a pluggable **`CaptureBackend`** interface; the operator picks a mode per session.

| Mode | Placement | Control | Best for | Trade-offs |
|---|---|---|---|---|
| **Userspace transparent bridge** (primary) | Two NICs, physically inline; frames captured on IF-A → pipeline → re-injected on IF-B, and B→A | Full **L2–L7**, deterministic | Physical inline insertion (copper or fiber) | App death darkens the wire → needs watchdog + fail-open policy (§8) |
| **NFQUEUE (kernel-assisted)** | Host is a routed hop/gateway; `FORWARD`/`PREROUTING` → userspace queue | **L3–L7**, kernel handles routing | Box is the gateway | L2 rewriting limited |
| **Bridged NFQUEUE** | Linux bridge + `br_netfilter` → NFQUEUE | L3–L7 on a transparent bridge | Transparent inline without userspace forwarding | Kernel bridge+nfqueue quirks; iptables does **not** see bridged frames unless bridge-nf is enabled |
| **ARP/NDP spoofing (on-path)** | Shared segment; poison caches to draw traffic through us → NFQUEUE | L3–L7 | On-path without re-cabling | Noisy, detectable |
| **Passive tap / SPAN / optical tap** | Mirror port or fiber tap | Read-only | Recon/baselining | No manipulation |

### Recommended core: userspace transparent bridge
Two interfaces in promiscuous mode with **no IP addresses** (L3-invisible). We own forwarding, so we can rewrite anything — MACs, VLAN/QinQ tags, EtherType, IP options, TCP flags, payloads — and drop/delay/duplicate/reorder/inject. Avoids kernel bridge+NFQUEUE quirks entirely.

**Why not just the kernel bridge:** for a bridged interface the kernel installs `br_handle_frame()`, which won't hand frames to the normal input path (except STP/LLDP or when brouting). iptables/arptables sit in the routing stack and don't see bridged traffic unless `br_netfilter` is loaded. A userspace bridge sidesteps all of this and gives total control.

---

## 3. Capture/forward backends (all link speeds — mandatory ladder)

One `CaptureBackend` interface, several implementations, selected by throughput need and hardware:

| Backend | Throughput ceiling | When | Notes |
|---|---|---|---|
| **AF_PACKET (TPACKETv3) / libpcap** | ~1–2 Gbps | Default, universal | Works on any NIC/driver; the compatibility floor |
| **AF_XDP** | ~10–40 Gbps | Modern middle ground | Kernel-bypass-lite; keeps host a real Linux box; needs XDP-capable driver |
| **PF_RING ZC** | 10–100G | High-speed copper/fiber | Zero-copy; needs PF_RING modules |
| **DPDK** | 100G line-rate | Dedicated high-speed box | Binds NIC to poll-mode driver; hugepages, CPU pinning; NIC leaves kernel control |

Reference numbers: PF_RING+DPDK ≈ 14.88 Mpps (line rate) at ~8% of one core, vs libpcap ≈ 4.5 Mpps at ~45% CPU (~3.3× gap), scaling linearly toward 148 Mpps/100G on multiple cores. The pipeline above the backend is identical regardless of backend, so scaling up never touches rules, GUI, or dissection.

**Design rule:** the forward loop is a narrow interface (`recv_burst()` / `send_burst()`), so a Rust/C fast-path for AF_XDP/DPDK can replace the Python loop later without rewriting anything above it (§12).

---

## 4. Core capabilities

### 4.1 Live capture & dissection (Wireshark-lite)
- Real-time packet list (time, src/dst, protocol, length, info), color rules, BPF capture filters, Wireshark-style **display filters** with saved filter library.
- Full protocol **tree/detail view** + synchronized **hex/byte view**.
- Follow TCP/UDP stream; flow/conversation table; protocol-hierarchy and per-host stats; **expert info** (malformed, retransmits, checksum errors).
- pcap/pcapng import/export; ring-buffer capture-to-disk with rotation and size caps.

### 4.2 Inline manipulation (the heart)
- **Match → Action rule engine.** Match = BPF expression **plus** structured per-field conditions (e.g. `tcp.dstport == 502 && ip.src in 10.0.0.0/24 && modbus.func == 6`). Actions:
  - **Rewrite field** — any header field to a literal, computed, or scripted value.
  - **Payload edit** — hex/byte splice, regex/string search-and-replace, insert/delete bytes.
  - **Drop**, **delay/jitter** (latency injection), **duplicate/replay**, **reorder** within a flow, **rate-limit/throttle**.
  - **Corrupt/fuzz** (§4.5).
  - **Inject** a new packet alongside or instead.
- **Automatic recomputation** of lengths and checksums (IP/TCP/UDP/ICMP) on every modification — with a manual override to *intentionally* leave them wrong (for testing endpoint behavior).
- **Interactive intercept & edit** (Burp-Repeater-for-packets): a matched packet is *held* in an interception queue; operator sees an editable field tree + hex editor and chooses **forward / drop / forward-modified**. Manual and automatic modes coexist. Ordered rule pipeline with per-rule hit counters and enable/disable.

### 4.3 Packet crafting & transmission (build from scratch)
- **Visual packet builder:** stack layers from a palette (Ethernet → VLAN/QinQ → IP/IPv6 → TCP/UDP/ICMP → app protocol); **every header and data field editable**, with defaults, validation, and per-field "auto vs manual" toggles (so checksums/lengths can be forced wrong on purpose).
- **Raw hex editor** for arbitrary/non-standard frames.
- **Templates & library:** save/load/parameterize packets; build sequences and bursts.
- **Send controls:** one-shot, N-times, timed loop, or scripted burst; choose egress interface and L2/L3 send mode.
- **Send-and-receive:** transmit and match replies (sr/sr1-style) to view responses inline.
- **Edit-and-resend:** drop any captured packet straight into the builder as a starting template.

### 4.4 Protocol coverage — *all protocols*
- **IP stack:** Ethernet, 802.1Q/802.1ad (VLAN/QinQ), MPLS, PPPoE, ARP, IPv4/IPv6 (full parity), ICMP/ICMPv6, TCP, UDP, SCTP.
- **Multicast & broadcast (in scope):** unicast, **multicast, and broadcast** all handled for capture, manipulation, and crafting. Includes L2 broadcast/multicast MAC framing, IPv4 multicast + **IGMPv1/2/3**, IPv6 multicast + **MLDv1/2**, and broadcast-based protocols (ARP, DHCP discover, NetBIOS, mDNS/LLMNR, SSDP). Group membership and BUM (Broadcast/Unknown-unicast/Multicast) traffic can be observed, rewritten, dropped, injected, or replayed like any other frame.
- **App layer:** DNS, DHCP/DHCPv6, HTTP, TLS (metadata/SNI), mDNS, LLMNR, SSDP, NTP, SNMP, SMB, and more via Scapy contrib.
- **Non-IP / L2 control:** STP/RSTP, LLDP, CDP, LACP, ARP, EAPOL/802.1X.
- **Industrial / OT:** Modbus, DNP3, S7comm, EtherNet/IP/CIP, PROFINET, EtherCAT, IEC-104, BACnet (Scapy contrib as the seed; extend as needed).
- **Custom/proprietary dissectors:** operator-defined field layouts, enums, and length semantics so any protocol gets the same tree-view + field-level manipulation as built-ins. A dissector-definition format (declarative + Python escape hatch) is a core deliverable given "all protocols matter."

### 4.5 Fuzzing & mutation
- **Field-aware fuzzing** (Scapy `fuzz()`): randomize by field type (number/string/enum/length) within valid ranges, sent in a loop.
- **Mutation fuzzing** of captured/crafted packets (byte flips, swaps, boundary values); optional bundled offline mutation engine (Radamsa-style).
- **Sequence/stateful fuzzing** hooks for protocol state machines; response/anomaly monitoring to flag crashes or unexpected replies.

### 4.6 Stateful flow handling (advanced, high-risk)
- TCP stream reassembly for content-level edits.
- **Length-changing edits** require **sequence/ack fix-ups** for the rest of the flow — genuinely hard, can desync connections. Isolated module, heavily tested, shipped behind a flag.
- Connection-state tracking so rules can act on flow context, not just single packets.

### 4.7 Scripting & extensibility
- Python **plugin API**: `on_packet(pkt, ctx) -> action` and dissector plugins, with full Scapy access.
- Plugin manager (enable/disable, ordering, resource limits).
- **Headless/CLI mode:** everything the GUI does is scriptable for automation and regression.

### 4.8 Sessions, logging & reporting
- Session bundles capture + rules + crafted-packet library + results + interface config.
- **Structured event log** of every match and modification (what matched, what changed) — doubles as engagement evidence and as troubleshooting data.
- Export: pcap/pcapng, JSON event log, engagement report.

---

## 5. GUI design

### 5.1 Framework
**PySide6 (Qt 6, LGPL).** Wireshark itself is Qt; Qt handles dense high-refresh tables, hex/tree widgets, and modern theming well; one language with the Scapy engine. Alternatives (Rust/Tauri, GTK4) weighed in §12/§5.4.

### 5.2 Layout
- **Top bar:** interface/mode selector, bridge status + fail-open indicator, backend selector, start/stop, global kill-switch.
- **Left dock:** session tree, saved rules, display-filter library, crafted-packet library, plugins.
- **Center:** live packet list (color-coded) ↔ **intercept queue** tab (held packets).
- **Bottom/right dock:** synchronized protocol **tree** + **hex editor**, editable in place.
- **Rule builder:** visual match→action editor with live preview ("would have matched N of last capture").
- **Packet builder:** layer palette + field forms + hex + send controls.
- **Diagnostics panel:** health checks, live counters, log viewer, one-click fixes (§9).
- **Dashboards:** throughput, drops, per-protocol counts, active flows, rule hit counters, per-CPU load.

### 5.3 UX principles
- Never freeze under load: capture/dissection off the UI thread, virtualized tables, backpressure, adaptive detail (stop deep-dissecting every packet at high pps, dissect on selection).
- Stylized modern theme (dark default + light), keyboard-driven power-user shortcuts, clear **armed vs pass-through** visual state, undo/redo for rule and builder edits.

### 5.4 Framework trade-off (decide up front)
Pure Python (Scapy + PySide6) — fastest to build, richest manipulation, recommended for v1. Hybrid (Python control plane + Rust/C AF_XDP/DPDK fast path) — best long-term for line-rate. Pure Rust (Tauri + libpnet) — smallest airgap binary, weaker crafting ergonomics. **Start Pure Python; keep the forward loop swappable.**

---

## 6. The pitfalls that break inline tools (must-handle) 

These are the classic footguns; the tool must handle each **automatically** and expose them in Diagnostics.

- **NIC offloads corrupt the wire view.** With TSO/GSO/GRO/LRO/checksum-offload on, the stack shows oversized pseudo-packets (e.g. 30 KB on a 1500-MTU link) and "bad" outbound checksums, because tools tap above the NIC. The app must **auto-detect and disable** offloads on capture interfaces via ethtool (`tso off gso off gro off lro off rx off tx off`) and warn if it can't. This is the single most common reason manipulation "silently doesn't work."
- **Host stack interference.** In inline/bridge modes the host kernel may itself answer traffic it observes — sending TCP **RSTs**, ARP replies, ICMP, or completing handshakes — corrupting the engagement. Mitigate: no IPs on capture NICs, disable IPv6 autoconf on them, drop host-originated RST/ARP on those interfaces (arptables/nft), and disable `br_netfilter` local delivery where relevant.
- **MTU / fragmentation / jumbo frames.** Edits that grow a packet past MTU must fragment or be rejected cleanly; jumbo-frame links need MTU set on both NICs; PMTUD interactions surfaced.
- **VLAN/QinQ/MPLS tag handling** in bridge mode — tags must survive forwarding unless explicitly rewritten; NIC VLAN offload can strip/insert tags unexpectedly (disable it).
- **Broadcast & multicast (BUM) forwarding.** A userspace bridge must forward broadcast, unknown-unicast, and multicast frames across both ports, not just learned unicast. The kernel bridge's **IGMP/MLD multicast snooping** can silently prune multicast to ports it thinks have no listeners — disable snooping (or account for it) so multicast traffic isn't dropped inline. Promiscuous + `allmulti` must be set so the NIC delivers all group traffic. Injected/crafted multicast/broadcast must use correct group MAC mapping.
- **Drop accounting & backpressure.** Every dropped/queued packet must be counted and surfaced; the pipeline must apply backpressure rather than silently losing traffic at high pps.
- **Packet ordering & latency budget.** Inline processing adds latency; multi-queue/RSS NICs can reorder. Track added latency and preserve per-flow order.
- **Clock/timestamps.** Prefer hardware timestamping where available for accurate analysis; expose which source is in use.

---

## 7. Hardware, media & compatibility (copper + fiber, all speeds)

- **Media is mostly transparent to software:** copper and fiber both present Ethernet frames; fiber differs in the **NIC/SFP** and physical tapping, not the packet logic. Support SFP/SFP+/QSFP NICs.
- **Hardware bypass NICs** (e.g. Silicom/Napatech, copper and fiber) provide guaranteed **fail-open**: on host failure/power loss/software request the two ports are physically joined so the link survives. Modes typically: Normal / Bypass / Disconnect (Linkdrop). The app should detect bypass-capable NICs and drive their mode (watchdog-armed) — the clean answer to "don't take down the wire if the tool crashes."
- **Optical/passive taps and SPAN** for read-only capture where inline insertion isn't allowed.
- **Driver/feature matrix** maintained in-app: per-NIC support for AF_XDP, DPDK, PF_RING, hardware timestamping, VLAN offload behavior, bypass. Diagnostics reads this to pick a viable backend automatically.
- **Fiber high-speed reality:** 10/25/40/100G links effectively require AF_XDP/PF_RING/DPDK and CPU pinning/hugepages; document per-speed recommended backend + tuning.

---

## 8. Operational reliability (functional, not "safety")

- **Fail-open vs fail-closed watchdog** for bridge mode: hardware bypass NIC if present, else a kernel-bridge fallback, else configurable link-down. A heartbeat from the forward loop arms it.
- **Global kill-switch:** instantly revert to clean pass-through (or link-down) regardless of active rules.
- **Crash recovery:** persist session/rules/interface state; on restart, restore and offer to re-arm; never leave interfaces in a half-configured state (idempotent setup/teardown of ethtool/nft/ip settings, with automatic revert on exit).
- **Dry-run / shadow mode:** show what *would* change without altering traffic — the primary way to validate rules before arming.
- **Resource governance:** capture-buffer memory caps, disk rotation, CPU/core assignment, graceful degradation under overload.
- **Privilege separation (operational hygiene, not gating):** unprivileged GUI + a thin privileged helper holding `CAP_NET_RAW`/`CAP_NET_ADMIN` over a local socket, so a GUI crash can't wedge the NICs and the whole app needn't run as root.

---

## 9. Diagnostics & troubleshooting subsystem (first-class, operator-repairable)

The operator must be able to see what's wrong and fix it without leaving the app.

### 9.1 "Doctor" / self-test panel
On demand and at session start, run checks with pass/fail + one-click remediation:
- Interfaces exist, link up, correct speed/duplex, promiscuous mode on.
- **Offloads disabled** on capture NICs (auto-fix: run ethtool).
- No IP / no IPv6 autoconf on capture NICs (auto-fix).
- Required kernel modules loaded (`nfnetlink_queue`, `xt_NFQUEUE`/`nft` queue, `br_netfilter` for relevant modes) (auto-fix: modprobe).
- Firewall rules installed correctly for the chosen mode (auto-fix: (re)install).
- **Packets actually arriving** at the queue/bridge (live counter) and **forwarding both directions** (A→B and B→A counters).
- Privileged helper alive; capabilities present; hugepages/CPU isolation configured if DPDK.
- Host-stack suppression active (no stray RST/ARP).

### 9.2 Live health dashboard
Green/red indicators + live counters: pps/bps in/out per interface, drops (per stage), queue depth, rule hit rates, per-CPU utilization, added latency, error rates. A red tile links straight to the failing check and its fix.

### 9.3 Packet-path tracer
"Why didn't my rule match / why isn't traffic flowing?" — pick a packet or flow and see where in the pipeline it was seen, matched, modified, dropped, or forwarded, with the reason. Directly answers the two most common operator questions.

### 9.4 Loopback / end-to-end self-test
Inject a known marker packet, confirm it traverses capture → rules → modify → egress and comes out changed as expected. Validates the entire chain before an engagement, in seconds.

### 9.5 Log viewer + diagnostic bundle
In-GUI log viewer with severity filtering and search. One-click **export diagnostic bundle** (logs + config + interface/ethtool/nft state + rule set + counters + versions) as a single file for offline analysis — the thing the operator sends when asking for help.

### 9.6 Bundled offline knowledge base
Common-issue guide shipped with the app (no internet): "captures show 30 KB packets" → offloads; "connections reset" → host RST; "rule never matches" → tracer + filter tips; "no throughput at 10G" → backend/tuning. Each entry links to the relevant Doctor check.

---

## 10. Configuration & content management

- **Profiles/presets** per engagement (interfaces, mode, backend, tuning, rules, dissectors) — export/import as a single file for airgap transfer.
- **Versioned rule sets** with diff/rollback; undo/redo.
- **Offline content updates:** dissectors, plugins, and knowledge-base entries importable as **signed bundles** via USB — the airgapped analogue of an update, with integrity verification on import.

---

## 11. Technology stack (recommended)

| Layer | Choice | Notes |
|---|---|---|
| Language (engine + GUI) | **Python 3.12+** | Scapy ecosystem; fast iteration |
| Dissection/crafting | **Scapy 2.7+** | Richest lib; auto checksums/lengths; contrib protocols |
| Capture/forward | **AF_PACKET → AF_XDP → PF_RING → DPDK** | Pluggable `CaptureBackend` ladder |
| Kernel inline path | **NFQUEUE** (`netfilterqueue`) + **nftables/iptables/ebtables/arptables** | Gateway/bridged modes |
| GUI | **PySide6 (Qt 6)** | Dense tables, hex/tree, theming |
| Interface control | **ethtool, iproute2, arptables** wrappers | Offload/host-stack/interface management |
| Packaging | **AppImage** + PyInstaller/Nuitka; offline **.deb** | Self-contained; Kali + Debian |
| Optional fast path | **Rust/C** AF_XDP/DPDK hot loop | Only if Python throughput insufficient |

**Environment already provisioned on this dev box:** Scapy 2.7.0, PySide6 6.10.3, netfilterqueue 1.1.0, nftables/iptables/ebtables/iproute2/tshark, plus `libnetfilter-queue-dev` + build toolchain.

---

## 12. Performance engineering (needed for fiber/high-speed)

- Pipeline stages on separate threads/cores; lock-free queues between capture, dissect, rule-eval, and egress.
- **CPU pinning / IRQ affinity / RSS** configuration surfaced and automatable; hugepages for DPDK.
- Zero-copy paths (AF_XDP UMEM, PF_RING ZC) where available.
- **Adaptive dissection:** cheap classification on the hot path; full tree-view dissection only for selected/held packets.
- Batched (burst) I/O across the whole pipeline.
- Hybrid escape hatch: replace only the forward loop with a compiled Rust/C fast-path behind the same `recv_burst/send_burst` interface — rules, dissection, and GUI unchanged.

---

## 13. Optional later modules
- TLS interception (cert-injection proxy) for HTTPS content edits.
- Wireless (802.11) monitor-mode capture/injection.
- Distributed/multi-sensor operation and a central console.

---

## 14. Phased roadmap

**Phase 0 — Foundations.** Repo scaffold; `CaptureBackend` + `Rule`/`Action` + dissector interfaces; privileged helper + local IPC; idempotent interface setup/teardown (ethtool/ip/nft) with auto-revert; logging; AppImage skeleton; **veth/netns lab** + tcpreplay harness.

**Phase 1 — Passive capture + dissection GUI.** AF_PACKET capture, Scapy dissection, packet list + tree + hex, BPF + display filters, pcap import/export, flow table + expert info.

**Phase 2 — Rule engine + NFQUEUE inline manipulation.** Match→action engine, field rewrite / payload edit / drop / delay, auto checksum/length fix-ups, dry-run mode, **offload auto-disable + host-stack suppression**, per-rule counters.

**Phase 3 — Userspace transparent bridge.** Dual-NIC forward loop, watchdog + fail-open/closed, bypass-NIC driving, full L2 manipulation, VLAN/QinQ handling, drop accounting/backpressure.

**Phase 4 — Interactive intercept & edit.** Interception queue, editable field tree + hex editor, forward/drop/modify, arm/pass-through state machine + kill-switch, crash recovery.

**Phase 5 — Packet crafting & transmission.** Visual builder, per-field auto/manual, templates/library, send / send-receive, edit-and-resend.

**Phase 6 — Diagnostics & troubleshooting subsystem.** Doctor panel + one-click fixes, health dashboard, packet-path tracer, loopback self-test, log viewer + diagnostic bundle, offline knowledge base. (Threaded through earlier phases; hardened here.)

**Phase 7 — Advanced protocols & logic.** Custom dissector format, ICS/OT protocols, fuzzing/mutation, plugin API, TCP reassembly + seq/ack fix-ups, stateful flow rules.

**Phase 8 — Performance & packaging.** AF_XDP → PF_RING → DPDK backends, CPU/IRQ/hugepage tuning, 10–100G validation, reproducible signed AppImage + .deb, docs.

---

## 15. Testing strategy
- **Isolated lab by construction:** network namespaces + `veth` pairs + Scapy/tcpreplay generators. Never test on unauthorized networks.
- Golden-file dissection tests vs known pcaps; round-trip property tests (dissect → modify → reserialize → re-dissect) with checksum/length assertions.
- Fault injection: watchdog/fail-open, offload-enabled, host-RST, MTU-exceeded, malformed input.
- Throughput/latency benchmarks per backend and per link speed; bridge soak tests (long-running, high-pps) for leaks/backpressure.
- Diagnostics self-test coverage: each Doctor check has a corresponding failing-condition test.

---

## 16. Risks & open items
- **Inline availability:** userspace bridge = single point of failure → mitigated by bypass NIC + watchdog + fail-open.
- **TCP length-changing edits:** seq/ack fix-ups can desync flows → isolated, flagged, heavily tested.
- **Bridge+NFQUEUE quirks:** prefer userspace bridge; validate kernel path early.
- **Python throughput ceiling:** mitigated by backend ladder + Rust/C fast-path.
- **DPDK footprint on airgap:** hugepages/driver binding complicate packaging → document, automate via Doctor, keep AF_PACKET/AF_XDP as no-special-setup fallbacks.
- **Still-open questions:** any specific proprietary protocols to prioritize first? preferred primary link speed for the initial hardware target (drives which backend to harden first)? bypass-NIC hardware available, or must fail-open be software-only initially?

---

## 17. Selected references (state of the art)

- NFQUEUE + Scapy inline modification — [byt3bl33d3r: Using Nfqueue with Python the right way](https://byt3bl33d3r.github.io/using-nfqueue-with-python-the-right-way.html), [scapy_altering_on_the_fly](https://github.com/gmonarque/scapy_altering_on_the_fly), [NetfilterQueue (PyPI)](https://pypi.org/project/NetfilterQueue/0.9.0)
- High-performance capture — [AF_XDP vs DPDK in 2026](https://eduardvasile.ro/blog/af-xdp-vs-dpdk), [XDP/eBPF fundamentals](https://labs.iximiuz.com/tutorials/ebpf-xdp-fundamentals-6342d24e), [PF_RING/DPDK capture](https://johal.in/pf_ring-packet-capture-python-dpdk-for-high-speed-network-monitoring/)
- MITM/manipulation tooling — [Bettercap](https://www.bettercap.org/legacy/), [Kali: bettercap](https://en.kali.tools/?p=140), [Scapy (Wikipedia)](https://en.wikipedia.org/wiki/Scapy)
- Transparent bridge / L2 & host-stack — [Transparent bridge on Linux](https://oneuptime.com/blog/post/2026-03-20-transparent-bridge-no-ip-linux/view), [ebtables bridge-nf](https://ebtables.netfilter.org/documentation/bridge-nf.html), [Linux bridge isolation](https://vincent.bernat.ch/en/blog/2017-linux-bridge-isolation), [Kernel: Ethernet bridging](https://docs.kernel.org/networking/bridge.html), [Arptables](https://en.wikipedia.org/wiki/Arptables)
- Offload gotchas — [Segmentation/checksum offloading with ethtool](https://sandilands.info/sgordon/segmentation-offloading-with-wireshark-and-ethtool), [Kernel: segmentation offloads](https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html)
- Bypass/fail-open hardware — [Silicom bypass adapters](https://www.silicom-usa.com/pr/server-adapters/networking-bypass-adapters/gigabit-ethernet-bypass-networking-server-adapters/pe2g2bpi35a-ethernet-bypass/), [Network TAP guide](https://www.niagaranetworks.com/products/network-tap-how-to-guide)
- Fuzzing/crafting — [Scapy usage docs](https://scapy.readthedocs.io/en/latest/usage.html), [Fuzzing proprietary protocols with Scapy + Radamsa](https://www.blazeinfosec.com/post/fuzzing-proprietary-protocols-with-scapy-radamsa-and-a-handful-of-pcaps/)
- GUI — [Wireshark Qt UI](https://www.wireshark.org/docs/wsdg_html_chunked/ChUIQt.html), [Tauri vs Qt 2026](https://rustify.rs/articles/rust-tauri-vs-qt-2026)

---

*For authorized security testing and research use.*
