# b50 / LX.37 — independent architecture review gate (GLM)

Status: PRE-FLIGHT COMPLETE, MERGE NOT RESOLVED, NOT BUILT. This is a proposal, not an implemented candidate.

## Immutable inputs

- accepted b49 core/workflow: `6cbf8682938577d08f35defb3b11b447fafaa831`; CI run `45973640257` success
- accepted b49 Apple source: `aa80f0abf8f603c33898f7c4cebdcdc9a1ec08fc` (fix/b49-logical-provider-nodes)
- upstream old: `b5db574026d89c70136cb488a755da6398d6cfc8` (v1.14.4-lx.36)
- upstream new: `92041d1a1bed6633a153a63d37ccc954f66c2d61` (v1.14.4-lx.37)
- separate branch: `build/b50-lx37-migration`
- preflight workflow commit: `74b6f7d66a858081b40efeaf9230fa7870c02bd0`
- actual preflight: https://github.com/eliassmail-dotcom/sing-box/actions/runs/45982774696
- review upstream release notes and SPEC 138 / 165 / 166 at the pinned release, not HEAD.

Full recursive Git tree comparison: 464 upstream paths changed, 23 overlapping changed paths (22 outside CI, one upstream CI workflow). Git apply --3way --index, excluding upstream workflows, reported 8 unmerged files / 20 conflict markers. No compile or release attempted.

## Proposed resolution

1. box.go: retain LX.37 initialization/validation for outbound manager, DNS manager, DNS router and router validation. Retain b49 warmup ownership transfer only after all fallible initialization succeeds. Test error cleanup.
2. common/dialer/resolve.go: port the b49 generation-aware IP race to the new resolveParallelNetworkDialer.DialParallelNetwork API; distinguish pre-resolved addresses from domain lookup, preserve single-address and normal dialer semantics, cancellation and generation invalidation. Do not reintroduce removed DialSerialNetwork or bypass verified TLS.
3. common/tls/client.go: retain LX.37 per-call config and cloned ECH retry (including kTLS wrapper handling); integrate authenticated DialVerifiedTCP into that path. Clone per attempt, preserve adaptive record fragmentation, FinalMask, sniff guard, proof of REALITY authentication and close losers. No shared mutable TLS config and no downgrade fallback after authentication failure.
4. protocol/group/urltest.go: use LX.37 upstream hook/pool architecture (not b49 whole-file replacement); port custom validation and state to lxURLTest/lxURLTestGroup in urltest_hooks_lx.go. Preserve b49 priority_outbounds + secondary_priority_outbounds, tolerance_percent/min_hold, passive_guard, urls, startup warmup planning, forced retest behavior and UI routing identities. Round_robin self-heal remains upstream-owned; keep its probe hook, batch history commit, queue, network-change freeze, quarantine, cancellation and retry. Multi-URL must preserve one logical outcome per node, not count each URL as a separate failure or bypass the shared queue. Review every changed caller, including API, nested groups and diagnostics.
5. protocol/group/urltest_failover_lx.go: route probes through new hook and preserve multi-URL behavior; preserve upstream hold/degradation and custom priority/guard behavior where applicable. Ordinary provider failover and Smart three-tier selection must remain distinct; no new visible groups.
6. protocol/group/urltest_penalty_lx.go: keep LX.37 actual-leaf attribution, leafCtx, pathDead/refused distinction and cancellation semantics; reapply guard around fallback TCP without double-counting failures or double wrapping. Preserve reachability updates and interrupt policy.
7. protocol/group/urltest_selected_lx.go: adopt coherent atomic selection semantics of LX.37. Reconcile b49 conditional selection updates with CAS or a single writer lock that covers all writes; no mixed bare access or second independent synchronization domain. Preserve min hold accounting, cold start and selection change notifications.
8. protocol/group/urltest_tick_lx.go: use LX.37 monotonic rrClock/rrTime; keep new context probe hook plus multi-URL logic and b49 warmup planning.
9. Inspect all 22 overlapping non-CI files, not just conflicts; notably libbox build flags, dialer/default_parallel_interface, dialer/dialer, standard/uTLS clients, common/urltest, daemon/started_service, experimental/libbox/command_server, selector, VLESS, route/network and reachability. Clean textual merge is not evidence of semantic compatibility.

## Critical chain compatibility (requires agreement)

LX.37 SPEC 165 replaces per-chain node clones with global detour rewrite; chain idle_timeout, strip, strip_evasion and root lx.mtu_align are rejected. A leaf used directly and at chain position >=1 is now routed through the lower hop everywhere. Two chains sharing the same exit can also conflict.

Actual b49 Apple Library/Network/LXGeminiBuilder.swift: uses the same source leaf in the direct/mixed/manual groups and a type: chain ["Стратегия", leaf] with idle_timeout "5m" (lines 90–145); supported leaf types include wireguard. Thus merely deleting idle_timeout will NOT preserve routing. SFUnitTests/LXGeminiBuilderTests.swift contains testGeminiChainsUseDynamicStrategyAsFirstHop; extend it rather than removing the assertion.

Current Yandex generator app/index.js (feature/v2.0-alpha-corp-port, blob acca687ef9ee428ec9b579e1730b34c2988a39c7) already constructs distinct VLESS tags with explicit detour for Russia and Strategy paths; validate those profiles as-is. No Yandex changes in this migration.

Proposed: keep native LX.37 chain behavior for new configs. For b49 on-device Gemini builder, separate stateless exit instances by path (stable existing visible tags; direct leaf untouched, chain copy references dynamic Strategy, no additional user-facing groups). Avoid blindly duplicating stateful WireGuard/Tailscale keys. Agree how to support imported legacy chains and shared stateful nodes before code: a scoped legacy path or explicit normalization with validated route equivalence; do not silently change routes or silently drop legacy fields. Generic conversion of chain-specific strip to global strip is not equivalent. Preserve explicit record_fragment and assess the new detour strip defaults in every TLS path. Preserve original subscription bytes and apply migration only to effective config. Guard against cycles and duplicate tags. Hide internal chain-hop entries by type in UI, without hiding user groups. Assess removed libbox APIs and new ABI by compiling the actual Apple client; checked selected files at b49 have no references to removed chain methods, but this is not an exhaustive audit.

## Dependency pins from upstream tree

- sing-tun: 9204da09505e864d98129e8737da71b06926e0bc
- wireguard-go: e587a0f47cfe9b103f134437ebe9a6751677265b (also review .gitmodules URL/branch)
- uTLS: 5b1d579d14864b13e142c3567ddfd4fcd320bf57 (unchanged)
- gVisor: 117243aa02fa2915cb53d1d4549bfca3a3ebf238 (unchanged)
- use exact upstream module pins and Apple production build tags, not floating branches.

## Acceptance and review gate

Retain b49 Go regression and race suite, all existing XCTest and IPA preflight/packaging gates, with unchanged Apple Bundle ID/entitlements/App Group/startup and logical provider node UX. Add tests for upstream RR self-heal and no false death on transient network outage, nested selection, canceled probes, proxy vs destination refusal, atomic selection races, multi-URL first success/cancel, TLS ECH clone + verified REALITY IP race, TCP/UDP/wake reset, chain direct/Russia/Strategy topology and legacy parser. Test local and Yandex effective profiles (personal, corporate/CD, guest, Gemini, chain on/off, Tailscale) without logging credentials; verify no direct-route leakage or DNS changes. Preserve previous tests, do not weaken gates or publish an IPA before success. Windows branch/build/release and production Yandex function remain untouched.

GLM is an independent reviewer, not an implementer. Please check actual pinned sources and preflight logs, challenge all proposed decisions, especially chain compatibility and atomic selection/multi-URL hooks. Return GO / CONDITIONAL GO / NO GO, with findings classified Critical / High / Medium / Low, exact file/symbol and evidence, required changes and test cases. Separate design verdict from code verdict; source changes and successful build are not yet available. No release before consensus and subsequent successful acceptance gates.
