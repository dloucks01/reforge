# Reforge — full code review & capability audit (2026-09)

A ground-up read of every subsystem: what exists and how mature it is, what the
design implies but the code does not yet deliver, and the concrete correctness
bugs found (with file:line and severity). Complements the operator-flow audit in
[CAPABILITY-AUDIT.md](CAPABILITY-AUDIT.md) and the offensive gap list in
[CAPABILITY-GAPS.md](CAPABILITY-GAPS.md). For authorized security testing only.

**Method.** Four parallel reads across the tree (inline core; attacks; offensive
add-ons; GUI/ops), each verifying the docs' "DELIVERED" claims against the code.
Baseline test health at review time: **609 passed, 26 skipped** (the skips are
root/live-gated). Scale: ~16.5k LOC source across 21 subpackages, ~9.7k LOC of
tests in 93 files.

Headline: the **pure, offline-testable core is genuinely solid and well-tested**
— rules, reassembly, seq/ack fix-ups, HTTP framing, dissection, mmap parsing,
crafting, and the offensive add-ons all match their claims. The weak spots are
concentrated in **code that needs root or live traffic** (the capture transmit
abstraction, NFQUEUE inject, privileged network config, live concurrency) and in
a handful of **crafted packets that are not wire-valid**, which unit tests that
assert only some fields did not catch.

---

## 1. What we have (maturity by subsystem)

| Subsystem | State | Notes |
|---|---|---|
| `rules/` (match→action engine) | **solid** | fail-open on match/action errors; GUI guidance helpers real; well tested |
| `core/` reassembly, seq/ack, framer, flows | **solid** | scope limits (single-segment edits, clean flows) documented |
| `core/bridge.py` userspace bridge | **solid, live-path caveats** | primary inline mode; concurrency/counter/echo edge cases (§3) |
| `capture/` afpacket, rawsocket, mmap ring, pcap, nfqueue | **solid capture; TX broken** | transmit abstraction had a latent crash (§3.1, now fixed) |
| `capture/perf_backends.py` AF_XDP/PF_RING/DPDK | **detection-only (honest)** | `open()` refuses cleanly; real zero-copy is a compiled component |
| `attacks/` ARP/DNS/DHCP/NDP/HTTP/TLS/creds | **mostly solid** | some crafted replies not wire-valid (§3); creds narrower than claimed |
| `fuzzing/` smart fuzzer | **solid, ~80% of spec** | gaps: stateful, minimization, persistence, rate, coverage |
| `evasion/`, `recon/`, `scan/`, `covert/` | **solid** | all real, all tested |
| `scenario/`, `engage/`, `distributed/` | **solid** | distributed ships optional mTLS + loopback-default warning |
| `craft/`, `plugins/`, `perf/` | **solid** | crafting/plugins/custom-proto all real |
| `gui/` (21 panels) | **solid, unusually well tested for Qt** | every backend capability has a panel except covert channels |
| `diagnostics/` doctor/tracer/selftest/health/kb | **solid** | pure and thoroughly tested |
| `privhelper/` | **partial — dead code** | helper/IPC unwired; GUI runs privileged directly (§2) |
| `testlab/` netns lab | **solid** | unit-covered where not root-gated |

---

## 2. What we still need (gaps the design implies)

**Priority 1 — safety / correctness the tool promises but does not deliver**

1. **Privilege separation is unimplemented.** `privhelper/helper.py` + `ipc.py`
   describe an unprivileged-GUI ↔ privileged-helper split, but nothing connects
   to it — no caller of `ipc.send_request`/`HELPER_SOCKET` outside the package.
   The GUI runs `nft` via `subprocess.run` directly (`gui/main_window.py:830-878`),
   so the whole GUI must be privileged. `diagnostics/doctor.py:79` even tells the
   user to launch a helper daemon that nothing talks to. Either wire the helper
   or drop the pretense.
2. **NFQUEUE can't inject or duplicate.** `capture/nfqueue.py:95-100` handles only
   `set_payload`; it drops `res.extra`, so `Duplicate`/inject actions silently
   no-op under NFQUEUE while working on the bridge. The rule engine advertises
   them uniformly.
3. **`recommend_backend()` can name an unrunnable backend.** For high link speeds
   it returns `dpdk`/`pf_ring`/`af_xdp` when the host "supports" them, but
   selecting one then throws at `open()`. Recommendation should fall back to the
   best backend that can actually open.

**Priority 2 — offensive capability narrower than the docs claim**

4. **Credential harvest is narrower than "DELIVERED".** Real: HTTP-Basic, HTTP-form,
   cookie, FTP, POP3, SMTP, SNMP. **IMAP is nominal/broken** (keys on POP3/FTP
   `USER `/`PASS ` syntax); **LDAP, Telnet, NTLM, Kerberos, HTTP-Digest absent.**
5. **Name-service poisoning is not wire-valid** (§3.2) — present but the forged
   answers source from a multicast/broadcast IP.
6. **NDP "RA flooding" is a single rogue RA**; `ndp.RogueRouter` is dead code.
   No ICMP-redirect / STP / DTP / VLAN-hopping (Tier-1 design list).
7. **DNS spoofing is A-record only** (§3.4) — no AAAA/other qtype.
8. **Custom-dissector capability is a plumbing shell** — `dissect/base.py` is
   interface + empty registry; no built-in custom dissectors ship (Scapy does
   the real dissection). Crafting's `custom_proto.py` is the real surface.
9. **Covert channels have no GUI panel** — full backend (`covert/`), reachable
   only as a scenario step.

**Priority 3 — fuzzing engine completeness** (the piece we set out to pick up)

10. `fuzzing/` delivers all four mutators, pcap seeding, response-feedback monitor,
    reproducible campaign. Missing vs the design in CAPABILITY-GAPS:
    **stateful fuzzing** (valid prefix then fuzz), **test-case minimization**,
    **corpus/findings persistence** (save/replay to disk), **rate/pacing**, and
    **per-field coverage** in the report.

**Priority 4 — real high-rate data plane** — AF_XDP/PF_RING/DPDK zero-copy loop
(today detection-only; a compiled component per deployment). Wireless (802.11)
remains a separate domain (Tier 3).

---

## 3. Correctness & quality findings (verified, by severity)

Line cites are to the tree at review time.

**HIGH**

- **§3.1 `Frame.egress` did not exist; `send_burst` crashed.** `capture/base.py`
  `Frame` had no `egress`, yet `afpacket.py:87` and `rawsocket.py:191` both read
  `f.egress` — `AttributeError` on the first frame. Every test used backends that
  override `send_burst`, so it was latent. **FIXED** in this pass (field added +
  regression tests `test_afpacket_send.py`, `test_rawsocket.py`).
- **§3.2 Name-service poison replies use a multicast/broadcast source IP.**
  `attacks/namepoison.py:73,92` build the answer as `IP(src=pkt[IP].dst, ...)`;
  for LLMNR/mDNS/NBT-NS the query's dst is the group/broadcast address, so the
  forged answer sources from a multicast/broadcast IP — malformed per RFC 1122,
  liable to be dropped by the victim. Should source from `our_ip`.
- **§3.3 Host-stack ARP suppression is non-functional.** `privhelper/netconfig.py:171`
  adds `arp drop` to an **`inet`-family** chain; nftables `inet` never sees ARP
  (needs `arp`/`netdev`). Host-originated ARP is not suppressed, defeating half
  the promised host-stack suppression.
- **§3.4 Revert journal records fixed values, not prior state.**
  `privhelper/netconfig.py:70-83` records offloads→`on`, promisc→`off`,
  allmulti→`off`, ipv6→`0` unconditionally. If any differed before prep, revert
  leaves the host in a *different* state than found — contradicting the module's
  core guarantee.

**MEDIUM**

- **§3.5 `tls_proxy` leaks sockets on the success path.** `attacks/tls_proxy.py:73-105`
  `_handle` has no `finally`; the HTTP-relay branch never closes `tls_client`/
  `tls_up`/`up`. Every intercepted HTTPS connection leaks fds. (`tcp_proxy.py`
  does this right with a `finally`.)
- **§3.6 Cross-thread socket send on intercept release.** GUI-thread `resolve()`
  → bridge `_egress_release` → `ScapyPort._send.send` runs concurrently with the
  bridge loop thread on the same non-thread-safe Scapy socket; the same closures
  mutate `BridgeCounters` from both threads without a lock (`core/bridge.py:68,237`,
  `core/intercept.py`).
- **§3.7 A `delay` action stalls the whole wire and can trip the watchdog.**
  `core/bridge.py:183` / `nfqueue.py:94` `time.sleep(delay_s)` inside the single
  forward loop blocks all flows; the heartbeat refreshes only per loop iteration
  and the CLI arms the watchdog at 2.0s, so a `delay` ≥ ~2s trips fail-open.
- **§3.8 Blocking privileged subprocess on the Qt UI thread.** `gui/main_window.py:843-878`
  runs `nft` in a loop with `subprocess.run` on the UI thread (also from
  `closeEvent`), stalling the event loop / window close.
- **§3.9 `dns_spoof` ignores query type.** `attacks/dns_spoof.py:52` always emits
  a type-A answer; an AAAA query gets a mismatched answer the resolver discards,
  and an IPv6 map value fails to serialize as A. Also `hostmap` keys are not
  lowercased for the exact-match lookup (`:21`).
- **§3.10 Console collector can bind 0.0.0.0 in plaintext.** `gui/console_panel.py:79,85`
  defaults mTLS on but lets the operator disable it and listen plaintext on all
  interfaces, against the tool's local-only posture. The label warns; nothing
  enforces loopback.
- **§3.11 Silent teardown-error swallowing in a MITM tool.** `gui/attacks_panel.py`
  swallows every `.stop()` exception (`except Exception: pass` at 313/319/371/405/
  449/608/659/782). A failed stop can leave ARP caches un-restored or forwarding
  enabled with no operator signal.

**LOW**

- **§3.12** NFQUEUE per-tick UI work, intercept re-dissect every 200 ms, and
  `_dry_run_over_capture` iterating synchronously — janky under load
  (`gui/main_window.py` `_drain`/`_refresh_flows`, `gui/intercept_panel.py`).
- **§3.13** `httpframer.py:88-92` buffers a no-CL, non-chunked response until
  connection close — unbounded on a keep-alive stream.
- **§3.14** Silent broad excepts hide real failures: `core/scapy_init.py:26`
  `warmup()`, `capture/registry.py:61` `list_interfaces()`, and the rule engine's
  match/action swallows (intentional fail-open, but never surfaced to counters).
- **§3.15** `ndp_mitm.py:56` relay counter compares against an unset `our_ip`
  (stat inflation). Bridge `modified` double-counted on the held-flow branch
  (`core/bridge.py:192,241`).
- **§3.16** `tls_ca.py:108` writes leaf cert files named from unsanitized SNI —
  a crafted SNI with path separators could write outside the temp dir.
- **§3.17** `netconfig.py` `suppress_host_stack` is not idempotent (stacks
  duplicate rules); `privhelper/helper.py:66` socket has no peer-credential check
  (mitigated by root-owned 0600 socket) and no read bound.
- **§3.18** `rules/spec.py:137` flags `strip_starttls` as length-changing though
  it is length-preserving (intentional defensive seq/ack arming; harmless but
  self-contradictory).

**Positives worth recording.** Iface names are strictly validated against
injection (`netconfig.py:25`, tested). The NFQUEUE runner uses a correctly joined
daemon thread. Scan/fuzz/scenario workers use the thread-then-`QTimer` pattern
with no cross-thread Qt widget access. `stop_capture` releases held packets so
none are stranded. `tls_ca` keeps the CA key in memory and chmods leaf keys 0600.
Pure/impure separation across attacks is consistent and genuinely unit-testable.

---

## 4. Test-coverage gaps

The offline core, rules, reassembly, crafting, diagnostics, and the add-on
subsystems are well covered. Blind spots that let the above bugs through:

- **Transmit paths** — `afpacket.py` had no test file; `rawsocket` send/ring paths
  are `pragma: no cover`. (§3.1 regression tests added this pass.)
- **Wire-validity of forged packets** — namepoison tests assert `dst`/`sport`/
  `rdata` but never `src` (§3.2); dns_spoof has no AAAA/type-mismatch case (§3.9).
- **Socket cleanup** — tls_proxy loopback test never checks for the fd leak (§3.5).
- **Privileged netconfig behavior** — tests cover iface validation only; the
  revert state-capture (§3.4) and inet-ARP (§3.3) bugs are untested.
- **Live concurrency** — cross-thread intercept release (§3.6) and delay-vs-
  watchdog (§3.7) are unverified.
- **Creds** — IMAP/LDAP/Telnet/NTLM/Kerberos/Digest untested (mostly unimplemented).
- **privhelper helper/IPC** — zero tests (consistent with being dead code).

---

## 5. Recommended fix order

1. **Wire-validity bugs** (cheap, high offensive value): namepoison source IP
   (§3.2), dns_spoof qtype + key casing (§3.9), tls_proxy fd leak (§3.5). Each is
   a pure builder or a `finally` — unit-testable without root.
2. **Privileged-config bugs** (§3.3 nft ARP family, §3.4 revert state-capture):
   correctness-critical for the tool's revert guarantee; validate on the netns lab.
3. **Fuzzing completeness** (§2.10): stateful, minimization, persistence, rate,
   per-field coverage — the piece we set out to build.
4. **NFQUEUE inject/duplicate** (§2.2) and **backend recommendation fallback**
   (§2.3).
5. **Privilege separation** (§2.1) — wire the helper or remove it; larger effort.
6. **Live-path hardening** (§3.6–3.8): move privileged subprocess + delay off the
   hot/UI thread, lock the shared counters.

Items 1 and 3 are underway in the same change set as this review.

---

## 6. Resolution log (this change set)

Worked in priority order from §5. Each fix shipped with regression tests; the
suite grew from 609 to 649 passing.

**Done**

- **§3.1 Frame.egress** — field added; afpacket/rawsocket send paths tested.
- **§3.2 name-service poison source IP** — answers now source from our own IP.
- **§3.9 DNS spoof qtype + key casing** — answers A vs AAAA by address family;
  hostmap keys matched case-insensitively.
- **§3.5 tls_proxy fd leak** — all sockets closed in a finally.
- **§3.3 host-stack ARP suppression** — moved to a dedicated arp-family table
  (inet never sees ARP); chains flushed so repeat calls don't stack rules.
- **§3.4 revert accuracy** — an injectable HostState reader records the real
  prior state; falls back to the old assumption only when state is unknown.
- **§2.2 NFQUEUE inject/duplicate** — res.extra rides an injectable injector
  (lazy L3 raw socket by default); an `injected` counter; failures count errors.
- **§2.3 backend recommendation** — BackendCaps.has_dataplane keeps
  recommend_backend on runnable backends; recommend_with_note flags a
  detected-but-unbuilt fast-path.
- **§3.7 delay vs. watchdog** — _sleep_delay refreshes the heartbeat in chunks;
  headless returns at once.
- **§3.6 cross-thread transmit** — all sends funnel through _emit() under an
  RLock; _sent access is locked.
- **§2.1 / helper ops** — the privileged helper now covers prepare_bridge,
  suppress_host_stack, NFQUEUE install/remove, fail-open/closed, and revert, with
  a tested HelperClient and a bounded request read. The doctor privilege message
  is corrected. Note: true privilege separation is inherently partial — the
  capture data plane needs CAP_NET_RAW in the app process and cannot be delegated
  over IPC; the helper takes over the network config only.

**GUI pass — done**

- **GUI wiring through HelperClient** — _start_inline/_stop_inline now install and
  remove the NFQUEUE diversion rules via the privileged helper when a helper
  socket is present (one IPC batch), falling back to direct nft when the GUI is
  itself privileged.
- **§3.8 (improved)** — routing through the helper collapses N per-call
  subprocess spawns on the UI thread into a single IPC round trip. The no-helper
  (root GUI) fallback still applies nft synchronously; moving that fully off the
  UI thread is a smaller follow-up.
- **§3.12** — the drain timer now runs only row-flush + hold-reap every 100 ms
  tick; the heavy refreshes (held-packet re-dissect, health meter, recon
  inventory, flows table) run at 1/5 that rate (_SLOW_TICK_EVERY).

**GUI pass — layout (done)**

- Attack panel clipping fixed (sections hosted in a scroll area).
- Live workspace favors the packet stream by default and grows the editor only
  once interception is armed; the Intercept apparatus collapses to a hint when off.
- Session-bar pill states the mode; the live packet/loss count stays in the
  bottom status bar (no more duplication).

**GUI pass — remaining**

- _dry_run_over_capture still iterates the whole capture synchronously on click.
- The no-helper (root GUI) nft fallback still applies synchronously (see §3.8).

**Low-priority findings — done**

- **§3.16** — SNI-derived cert filenames sanitized (`_safe_name`: strip separators
  + hash), so a crafted SNI can't escape the temp dir.
- **§3.13** — HttpFramer now caps the buffer on every incomplete path, so a peer
  that never terminates a message can't grow it without bound.
- **§3.17** — the helper checks `SO_PEERCRED` and refuses any peer that isn't root
  or its own uid (defense-in-depth over the 0600 socket); nft idempotency and the
  read bound were already fixed in the item-2/item-1 work.
- **§3.10** — the console collector binds loopback when mTLS is off (only exposes
  on all interfaces under client-cert auth).
- **§3.11** — attack teardown failures are logged and surfaced: ARP/NDP stops show
  a red "restore FAILED — check the target's cache" instead of a false success.
- **§3.15** — `ndp_mitm` sets `our_ip` in prepare(); the bridge no longer
  double-counts `modified` on the held-flow passthrough branch.
- **§3.14** — `warmup()` and `list_interfaces()` log a warning instead of hiding a
  broken Scapy import as success / "no interfaces".
- **§2.6** — added real IPv6 RA flooding (`ra_flood_packets`, `RaFlood`) and wired
  both `RogueRouter` and `RaFlood` into scenario steps, so neither is dead code.
- **§2.4 (partial)** — fixed the broken IMAP parser (tagged `LOGIN` +
  `AUTHENTICATE LOGIN`) and added HTTP Digest capture.
- **§3.18** — documented (no behavior change) why `strip_starttls` is listed as
  length-changing (defensive seq/ack arming).

**Still open** (larger efforts, not LOW)

- §2.4 remainder: LDAP simple-bind (BER decode), Telnet (char-at-a-time),
  NTLMSSP and Kerberos hash capture — each a real feature, not a one-liner.
- §2.8 built-in custom dissectors, §4 wireless / real fast-path data plane.
