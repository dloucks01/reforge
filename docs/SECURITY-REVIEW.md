# Reforge — security review (of the tool's own code)

Scope: the safety of Reforge itself — could it harm the operator's host, be
turned against the operator, or leave the system in a bad state. The offensive
capabilities are intended and out of scope. Reviewed the whole codebase; date
2026-09-07.

## Summary

The fundamentals are clean: **no** `shell=True`, `os.system`, `eval`/`exec`
(outside the deliberate plugin loader), `pickle`, or unsafe `yaml.load` — YAML
uses `safe_load`, all deserialization is `json`, and every `subprocess` call
passes an argument list (no shell). Three concrete hardening issues were found
and fixed; the rest are deployment recommendations for inherently powerful
features.

## Findings

### Fixed

1. **Privileged-helper socket permission race — Medium.**
   `helper.py` bound the root Unix socket and *then* chmod'd it to 0600, leaving
   a window where a non-root local user could connect and drive privileged
   network changes. **Fix:** create the socket under `umask(0o077)` so it is
   never world/group-accessible, then chmod.

2. **Interface-name argument injection — Low/Medium.**
   Interface names are interpolated into privileged `ip`/`ethtool`/`nft`/`sysctl`
   commands. They go in as list args (no shell), but a flag-like name (e.g.
   `-K`) could be misparsed as an option. **Fix:** strict validation
   (`^[A-Za-z0-9_.@:-]{1,64}$`, reject leading `-`) in every netconfig builder;
   invalid names raise `ValueError`.

3. **TLS-MITM leaf private keys left in /tmp — Low.**
   The dynamic CA writes per-host leaf keys to a temp dir (0700) for `ssl` to
   load. They were never cleaned up. **Fix:** explicit 0600 on each key file,
   and `close()` (registered `atexit`) removes the temp dir. The **CA private
   key never touches disk** (in-memory, ephemeral per instance).

### Recommendations (inherent to the feature; documented, not code bugs)

4. **Distributed collector transport is unauthenticated/unencrypted — Medium
   (networked use only).** Default bind is loopback. For sensors on another
   host, tunnel it (SSH/WireGuard) or restrict to a trusted segment; an exposed
   port lets an attacker inject false observations or read reported credentials.
   A security note was added to `distributed/network.py`. Future: optional mTLS.

5. **Plugin loader executes operator code — by design.** `plugins/` runs
   `register()` from `.py` files in a directory. Only load plugins from a
   directory you control and that is not writable by lower-privileged users.

6. **Intercepting proxies bind 0.0.0.0 and don't verify upstream — by design.**
   The TLS interceptor and TCP proxy must receive redirected victim traffic, and
   MITM intentionally does not verify the upstream certificate. Restrict the bind
   to the engagement interface/IP and firewall the listen ports so the proxy
   isn't an open relay.

7. **Engagement artifacts are sensitive at rest.** Sessions, scenario reports,
   diagnostic bundles, and pcaps can contain harvested credentials and network
   detail in plaintext. Store them encrypted / on removable media and wipe after
   the engagement. (At-rest encryption is a planned option, not yet implemented.)

## Notes checked and cleared

- No secrets/passwords committed in the repo.
- Randomness: TLS keys and serials use the `cryptography` CSPRNG; `random` is
  used only for non-security values (fuzzing, MAC/xid jitter, covert payloads).
- Session/template/scenario/protocol loading is data-only (json / `type()`),
  no code execution from data files.
- Helper socket is 0600, in the user state dir; helper never runs as full root
  from the GUI (privilege separation).

## Regression tests

`tests/test_security.py` covers the interface-name validation (good/bad names,
both bridge interfaces) and the TLS-CA key cleanup.
