# LX b35 — verified TCP/TLS/REALITY IP race

Experimental functionality; requires the **b35** patched Libbox core.
This branch is based on the full b34/b33 iOS application. Its existing
Dashboard, Config Studio r6, generator, URLTest, VPN first-start recovery,
universal signing preflight, and App Group handling are retained.

## Problem and approach

Some DNS names yield multiple IPv4 answers; one may accept TCP yet fail the
TLS/REALITY handshake. A TCP-only race can therefore choose a useless peer.

When `"tcp_concurrent": true` is set on a **direct domain-based outbound**,
the resolver races at most 3 TCP+TLS candidates with 75ms stagger. Each
candidate uses its own cloned TLS/REALITY config; the winner is recorded
only after **successful TLS/REALITY verification**, not a TCP accept.
Each address has a 1-second attempt cap when there are multiple candidates.
The existing request/URLTest timeout remains authoritative.

The last verified winner is cached for up to 10 minutes; failed addresses
are deprioritized for one minute. IP candidates always come from the current
DNS response. On network interface changes, VLESS resets this history.

Opt-in is **false** by default. No changes to non-opt-in connections,
UDP, domain name, TLS SNI, REALITY keys or original route rules.
`detour` and `tcp_fast_open` remain incompatible with this experiment;
do not enable on Russia-chain second hops.

## Testing and limitations

GitHub Actions runs Go race-detector suites for dialer, TLS, options,
VLESS and real-REALITY-vs-decoy tests. Swift unit tests, iOS archive,
embedded extension compatibility, and unsigned IPA preflight are run
by the b35 pipeline.

A passing CI run does **not** establish that the IPA has been signed correctly
or that VPN connectivity on a real iPhone/Wi-Fi path succeeds. Those remain
manual acceptance tests. The experiment is not an upstream LX release.
