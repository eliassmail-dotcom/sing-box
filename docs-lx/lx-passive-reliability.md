# LX Passive Reliability Guard (experimental, opt-in)

This module extends URLTest least_test / failover. It does not change routing
rules, OpenConnect, DNS, subscription generation, selectors, existing pools,
or the interruption preference. In particular, it does **not** turn ordinary
application timeouts into proof of DPI filtering.

## Enable

Inside an individual `urltest` outbound:

```json
{
  "type": "urltest",
  "tag": "Auto Smart",
  "outbounds": ["A", "B", "C"],
  "passive_guard": true,
  "interrupt_exist_connections": false
}
```

Default: `passive_guard: false`. Do not use with `mode: round_robin`:
validation rejects that combination. Nested URLTest groups have independent
guard state; enable only where you want this policy applied.

## Policy (first implementation)

- Passive observer: wraps the **proxied application stream** (not the raw
  VLESS/REALITY TLS socket). Never inserts a read timeout or edits payloads.
  A read that times out after an upstream request and 12–32 KiB received is a
  *weak* stall hint, never sufficient on its own.
- Path-dead dial observations are taken from the existing SPEC 054 error
  classifier (timeout / network unreachable, not cancellation or RST).
- Within 45 seconds, **three failing independent destinations** OR
  **two stalled independent destinations plus one path-dead destination**
  quarantine the leaf tag for 60 seconds. Many failures from the same
  broken website do not quarantine the proxy.
- On quarantine, remove the leaf's URLTest history and move held TCP/UDP
  selections to available alternatives using the existing no-Interrupt
  handoff. Regular tests skip quarantined leaf outbounds until expiry.
  Manual forced URLTests may probe them but do not shorten quarantine.
- When a tag is suspect, only one group-level proxy dial may be
  outstanding to it at once (context-cancellable). This is not a global
  TLS handshake gate and is **not** Singleflight; multiplexed transports
  may initiate multiple transport-level handshakes internally.
- Successful dial clears tentative dial-failure evidence, but not passive
  stalls or a currently active quarantine.

## Limitations and next work

- Does not detect a hanging read if the application sets no timeout and no
  error is returned. It cannot see actual wire packet counts or classify
  a 16 KiB / 25-packet filter with certainty.
- Next step: implement a controlled 24 KiB canary on a user-selected,
  trustworthy endpoint with a response-length check and bounded timeout.
  Do not use `generate_204` as a deep canary.
- Add iOS controls/diagnostic counters (observations, confirmed quarantine,
  expiration, fallback reason). Until then, the feature is explicitly opt-in
  through the JSON and should remain off for normal use.
- Go tests and an iOS runtime validation are required before release.
