# Reforge — capability flow audit & roadmap

A walk of every end-to-end capability as an operator runs it — the flow, how
smooth it feels, where it snags, and what to improve. Grounded in a full code
pass plus live E2E on the namespaced kernel range. For authorized engagements
only.

**Published page:** https://claude.ai/code/artifact/a1636304-f89d-4cd4-9566-30addf002fa2
(private artifact; dark terminal-console layout, 22 capabilities rated, 14
correctness bugs fixed in the pass, cross-cutting themes, prioritized roadmap).

## Roadmap — all five shipped

The audit surfaced five prioritized, cross-cutting improvements. All are now
implemented, tested, and committed on `main`:

| # | Improvement | Mechanism | Commit |
|---|-------------|-----------|--------|
| 1 | Inline preflight in Doctor | `run_inline_preflight()` checks FORWARD policy, rp_filter, IP-forwarding, NIC offloads, queue readiness; the GUI names any blocker with its one-line fix before arming | `f465769` |
| 2 | Auto-arm seq/ack fix-up | `rules_change_length()` auto-arms flow-rewrite for a length-changing rule on both engines; a length-changing interactive edit (which bypasses the fixer) warns instead | `e85c7a9` |
| 3 | "What landed" confirmation counters | DNS / NBNS-LLMNR / rogue-DHCP runners count seen-vs-acted; the Attacks panel polls them live, so a dead attack reads differently from a working one | `af13b16` |
| 4 | Guide NFQUEUE-vs-bridge choice | `recommend_inline_engine()` reads NIC count, MITM state, and the nfqueue stack, then names the engine and its trade-off at the mode switch and the intercept toggle | `4d4bdda` |
| 5 | Route multi-segment intent to the message relay | `rules_need_message_proxy()` flags whole-HTTP-message transforms on the per-segment path and points at the TCP-proxy relay with the equivalent transforms | `ecea29c` |

## Live verification (audit #4 and #5)

`tests/test_live_guidance.py` proves each guidance feature's premise on a real
kernel (`sudo REFORGE_LIVE=1 pytest tests/test_live_guidance.py`):

- **#5** — On the live lab the per-segment inline engine (userspace bridge) did
  not merely no-op a two-segment HTTP body: `http_inject` **mis-placed** the
  snippet at the first fragment's boundary (split-dependent corruption, since
  `parse_http()` only ever sees one segment), never adjacent to `</body>`. The
  `TcpProxy` message relay reassembled the whole message and injected correctly
  before `</body>`. The warning wording was sharpened from "missed" to
  **"missed or corrupted"** to match (`3328e37`).
- **#4** — `recommend_inline_engine()` reads the true interface count and the
  real nfqueue stack and points at the engine that works on this kernel: NFQUEUE
  under a live MITM, a userspace bridge given two NICs. Both recommended engines
  are re-proven to manipulate live traffic (`test_userspace_bridge_*`,
  `test_mitm_plus_nfqueue_*`).

Suite: 604 offline / 26 skipped; the 3 guidance live tests pass with clean
namespace + nft teardown.

## Updating the page

The page is a published Claude artifact, not tracked HTML. To revise it, edit and
re-publish to the same URL above (see the artifact tooling). This note is the
repo's durable pointer to it.

See also [CAPABILITY-GAPS.md](CAPABILITY-GAPS.md) for the offensive
capability/gap assessment this audit complements.
