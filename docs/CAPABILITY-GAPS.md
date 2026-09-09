# Reforge — offensive capability assessment & gaps

Where Reforge stands today and what to add, from an offensive/red-team
perspective. For authorized engagements only.

## What exists now (Phases 0-8)

- **Positioning:** userspace transparent bridge (physical inline, full L2-L7),
  NFQUEUE (routed), passive/pcap. Watchdog + fail-open, checksum fix-up,
  host-stack suppression.
- **Manipulation:** match→action engine (field rewrite, payload replace, drop,
  delay, duplicate, fuzz, plugin), interactive intercept & edit, TCP seq/ack
  fix-up (clean flows).
- **Crafting:** visual builder, send/loop/send-receive, edit-and-resend,
  templates, custom/proprietary protocol dissectors.
- **Extensibility:** Python plugin API, custom protocols, fuzz action.
- **Ops:** diagnostics (doctor/tracer/self-test/health/bundle/KB), no-install
  bundle, perf-backend detection + tuning.

This is a strong **inline manipulation core**. The gaps below are mostly
*attack modules and intelligence* built on top of it, not engine rework.

---

## Gaps & additions, by priority

### Tier 1 — highest offensive value, builds directly on the engine

1. **Active MITM positioning modules** — DELIVERED (ARP/DNS/LLMNR/mDNS/NBT-NS/DHCP/NDP):
   - ARP spoofing / cache poisoning; IPv6 **NDP** spoofing + RA flooding.
   - **DNS spoofing** as a first-class module (pattern→answer, wildcard, pinning).
   - **DHCP** starvation + rogue offers (gateway/DNS injection).
   - **LLMNR / NBT-NS / mDNS** poisoning (Responder-style name-service capture).
   - ICMP redirect, rogue router; STP root-takeover; DTP/VLAN hopping (double-tag).
2. **Credential & secret harvesting** — DELIVERED (attacks/creds.py):
   - FTP, HTTP-Basic/Digest/form, cookies, SMTP/POP3/IMAP (USER-PASS + AUTH
     LOGIN/PLAIN), SNMP community, LDAP simple bind, Telnet login, NTLM
     (NetNTLMv1/v2 hashes over HTTP), Kerberos AS-REQ pre-auth ($krb5pa$). Live
     "creds" feed + export via the Creds panel / distributed sensor.
3. **HTTP attack toolkit** — DELIVERED (attacks/http.py + http_actions.py):
   - **sslstrip / HSTS bypass**, HTTPS→HTTP downgrade, content & JS injection,
     response tampering, cookie/session manipulation, BeEF-style hook injection,
     **on-the-fly file replacement** (swap a download for a payload).
4. **Smart / intelligent fuzzing** — DELIVERED (reforge/fuzzing/): field-aware /
   dictionary / structure-aware mutators, pcap corpus, response-feedback monitor,
   stateful prefix, minimization, per-field coverage, persistence (see below).

### Tier 2 — force multipliers

5. **TLS interception** — DELIVERED (attacks/tls_ca.py, tls_sni.py, tls_proxy.py, starttls.py): dynamic CA, SNI parsing,
   STARTTLS downgrade, per-host bypass — unlocks HTTPS manipulation end-to-end.
6. **IDS/IPS evasion toolkit** — DELIVERED (reforge/evasion/): IP/TCP fragmentation and
   overlap, TTL/segmentation tricks, packet-in-packet, timing/obfuscation.
7. **Passive intelligence / recon** — DELIVERED (reforge/recon/): p0f-style OS + service/version fingerprint,
   asset discovery & network mapping from observed traffic, flow analytics,
   anomaly baselining.
8. **Active probing/scanning module** — DELIVERED (reforge/scan/): host/port/service discovery driven by the
   crafting engine (SYN/UDP/ARP sweeps, service probes), feeding the target list.
9. **Automation & scenario API** — DELIVERED (reforge/scenario/): headless campaign orchestration, scripted
   attack chains, MITRE ATT&CK technique mapping, richer engagement reporting.

### Tier 3 — larger/independent efforts

10. **Wireless (802.11):** monitor mode, deauth, evil-twin, WPA handshake
    capture + injection (separate adapter/domain). **ON INDEFINITE HOLD** — not
    planned for now (a separate RF domain + hardware); revisit only if an
    engagement requires it.
11. **Real high-rate data plane** — raw AF_PACKET + TPACKET_V3 mmap ring
    (reforge/capture/rawsocket.py) and **multi-core AF_PACKET via PACKET_FANOUT**
    (reforge/capture/fanout.py: N ring sockets, one drain thread each, kernel
    load-balances — RX scales with cores, no compiled component) both DELIVERED
    and runnable. The kernel-bypass tier (AF_XDP/PF_RING/DPDK zero-copy) is
    detection-only: the zero-copy loop is a compiled per-deployment component.
    Reforge discovers + loads an installed component via the provider contract in
    reforge/capture/fastpath.py; building/installing it is documented in
    docs/FAST-PATH.md.
12. **Distributed / multi-sensor** — DELIVERED (reforge/distributed/): multiple sensors report to a central collector.
13. **Covert channels / C2 testing** — DELIVERED (reforge/covert/): build & detect tunneled/exfil channels.

---

## Smart fuzzing — design (Tier 1, DELIVERED)

Today's `craft.fuzz` is *dumb* byte/bit mutation. "Smart" fuzzing adds
structure-awareness, guidance, state, and observation:

- **Strategies (mutators):**
  - *Byte/bit* (have): flips, sets, length-preserving.
  - *Field-aware:* mutate by field type — integers to boundary/overflow values,
    lengths to off-by-one/huge, strings to format-string/overlong/traversal,
    enums to invalid — then let Scapy rebuild (auto length/checksum).
  - *Dictionary:* inject known-bad tokens per protocol (magic values, `%n`, `../`,
    huge numbers, SQL/CMD metacharacters, boundary integers).
  - *Structure-aware:* corrupt one field while keeping the rest valid (deep
    reach), and deliberately desync length vs. payload.
- **Corpus:** seed from captured pcaps or crafted templates; keep "interesting"
  cases; save/replay for reproducibility (every case carries its seed).
- **Guidance (response-feedback):** since remote targets give no code coverage,
  steer by **observable response** — new/changed replies, error codes, resets,
  latency spikes — evolving inputs that produce novel behavior (genetic).
- **Stateful:** drive a protocol to a target state (a scripted prefix of valid
  packets) *then* fuzz, to reach deep logic.
- **Monitor & triage:** classify each response as normal / anomaly / **crash**
  (timeout, RST, 5xx, malformed, latency outlier); record the triggering input +
  seed, minimize, and flag for repro.
- **Campaign management:** iteration budget, rate, corpus evolution, per-field
  coverage, and a findings report.

Delivered incrementally: strategies + corpus + monitor + campaign runner first
(all offline-testable with a fake sender/target), then live send integration and
a GUI campaign panel.

**Status (2026-09): shipped.** `reforge/fuzzing/` implements all four mutator
strategies, pcap seeding (layer-filtered), the response-feedback monitor
(normal/no-response/reset/error/slow/crash), a reproducible campaign runner with
per-case seeds, **stateful fuzzing** (a valid packet prefix replayed before each
case), **test-case minimization** (`minimize.py`, ddmin), **corpus/findings
persistence** (save/replay to disk), **rate/pacing + a wall-clock budget**, and
**per-field coverage** in the report. The GUI Fuzzing panel drives it (seed,
strategies, rate, live campaign, save results). Offline-tested end to end.

---

## Recommended sequence

1. **Smart fuzzing engine** (requested) — DELIVERED (strategies, corpus, monitor,
   campaign, stateful, minimization, persistence, coverage).
2. **Credential harvester** + **active MITM modules** (ARP/DNS/DHCP/LLMNR).
3. **HTTP attack toolkit** (sslstrip/injection/file-replace).
4. **TLS interception**, then recon/fingerprinting and evasion.
5. Kernel-bypass fast-path (AF_XDP/PF_RING/DPDK compiled component), distributed
   — as the engagement profile demands. (Multi-core AF_PACKET fanout is already
   delivered; wireless is on indefinite hold — see item 10.)
