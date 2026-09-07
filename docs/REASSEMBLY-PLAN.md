# TCP stream reassembly — design & plan

The content transforms today (HTTP toolkit, injection, replace) and the
credential harvester operate on a single TCP segment. Real traffic spans many
segments, arrives out of order, retransmits, and overlaps. This plan makes
content inspection and rewriting correct across full streams. For authorized use.

## Why it's hard inline

- **Buffering vs. forwarding:** a transparent bridge must forward promptly; you
  can't hold a stream indefinitely to reassemble it (latency, memory, and you'd
  desync the peers).
- **Length-changing edits:** growing/shrinking a body shifts every later
  SEQ/ACK and must be re-segmented — the seq-fixer handles clean flows but not
  overlap/retransmit/reorder robustly.
- **Overlap & evasion:** overlapping segments with different data are the core of
  IDS/IPS evasion; the reassembler must apply an explicit, configurable policy.

## Architecture (two clean layers, one hard option)

### 1. Passive reassembler (do first — fully offline-testable)
`reforge/core/tcpreasm.py`:
- `TcpReassembler` keyed by the 4-tuple, one `DirectionBuffer` per direction.
- Track ISN and next-expected SEQ; hold out-of-order segments; dedupe
  retransmits by byte range; resolve overlaps by a policy (first/last/reject).
- Emit contiguous in-order bytes to a consumer as they become available.
- Handle FIN/RST teardown, gap timeouts, per-flow memory caps, SEQ wraparound.
- `HttpFramer` consumer: yields complete HTTP requests/responses (Content-Length
  / chunked aware) from the reassembled byte stream.

Integration: feed the capture tap into the reassembler so the **credential
harvester** and **HTTP analysis** see complete messages (fixes multi-segment
creds and bodies) — no re-injection risk, pure inspection.

### 2. TCP proxy mode (do second — the correct path for active rewriting)
Terminate matched flows locally and re-originate upstream (the way the TLS
interceptor already relays): the bridge/NFQUEUE redirects a matched flow to a
local `TcpProxy`, which reassembles both directions, runs the transforms on
complete messages, and writes a fresh, correctly-framed stream to the peer. This
sidesteps in-place re-segmentation entirely and is how mature MITM tools do
large-body rewriting.

- Reuse the `TlsInterceptor` relay pattern (select loop + `modify` hook).
- Original destination via SNI (TLS) or `SO_ORIGINAL_DST` (iptables REDIRECT) or
  the observed 5-tuple in bridge mode.
- The HTTP toolkit and injection run on `HttpFramer` output here, with correct
  Content-Length and re-chunking on the way out.

### 3. Transparent in-place rewrite (optional, hardest — later)
Keep bytes flowing through the bridge while rewriting in a sliding window, with
**per-flow byte-range delta tracking** (not just a cumulative counter) feeding
the seq-fixer, so retransmits/overlap/reorder stay correct. Bounded edits only.
This is the research-grade path; attempt after 1 and 2 are solid.

## Correctness checklist (must all be tested)

ISN handling · SEQ wraparound (32-bit) · out-of-order buffering · retransmit
dedupe · overlapping segments (policy) · missing-segment gap + timeout · FIN/RST
teardown · both directions independently · window/zero-window · memory caps &
flow eviction · chunked + Content-Length + gzip framing · connection reuse
(pipelining/keep-alive).

## Testing strategy

- Golden pcaps: benign HTTP (round-trip equals original), segmented, out-of-order,
  retransmitted, overlapping (each overlap policy), chunked, gzip, keep-alive.
- Property test: for any benign segmentation/reordering of a stream, reassembled
  bytes == original.
- Adversarial: overlap/TTL/segmentation evasion cases (also feeds the future
  IDS-evasion toolkit).
- Proxy mode: loopback client↔proxy↔server with multi-segment bodies; assert the
  transform applied and framing is valid end-to-end.

## Phasing

- **R1 — DONE** — `TcpReassembler` + `HttpFramer` + stream credential harvester.
- **R2 — DONE** — `TcpProxy` mode; HTTP toolkit runs on complete framed messages.
- **R3** — optional transparent in-place re-segmentation with byte-range seq-fix.

R1 is the foundation and is fully unit-testable with crafted/segmented pcaps;
start there.
