# b50 / LX.37 — peer review #3 packet (URLTest and CI)

## Immutable source inputs

- Known good b49: 6cbf8682938577d08f35defb3b11b447fafaa831; successful run 45973640257.
- LX.36: b5db574026d89c70136cb488a755da6398d6cfc8; LX.37: 92041d1a1bed6633a153a63d37ccc954f66c2d61.
- URLTest staged overlays: a3756f8c5ebff29bdf741c76d883da7254c8a52c, under migration/b50/resolved/protocol/group/.
- Apple candidate eae7921330d0e154b20a29db7c6051b9eab2a6bf; isolated Swift XCTest 18/18 (45987420101).
- CI source gate at 776b6284ed95fcb899f269c1a303ee3c83890ab9; run 45991844330.
- Full-feature Linux go build succeeded in 45991427192 and 45991844330; no feature removed. The first run stopped at vet: old Smart test composite literal plus unchanged deliberate TriggerGoPanic helper. The second run includes test adaptation and a precise known-warning check. Do not infer vet/race/native profile check success from go build.

## Decisions

1. Keep upstream SPEC 138 round_robin self-heal, no custom passive guard in round_robin. Retain opt-in b49 passive guard, Smart tiers, adaptive threshold/min_hold, manual rotation, multi-URL in least_test/failover. Retain upstream monotonic tick clock, batch history and actual leaf attribution.
2. Production selection uses atomic loads and one writer mutex. Normal health update rejects an expected pointer that is no longer current; dial fallback updates without interrupting streams. Test B50StaleHealthSelectionDoesNotUndoFallback covers stale health snapshot.
3. Keep full build tags derived from build_libbox. Cronet archive requires LLVM linker, now configured in Linux CI; no dependency downgrade or NaiveProxy removal.
4. Preserve source provenance: check conflict stage blob hashes, compare overlays before and after gofmt, verify upstream submodule SHAs. Test-only overlays are separately verified against base source. No release tag or IPA until review and acceptance.

## Reviewer checks (not yet signed off)

- Hook port: ensure all writers go through selectionWriter; verify no lock cycles with nested groups, manual rotation, passiveGuard and reachability. Check canceled/probe context and leaf attribution on fallback, guard wrapping once, no connection interruption beyond previous semantics.
- Verify failover holds, priority tier recovery, multi-URL logical result and upstream batch history under cancellation and nested groups.
- **Open issue RR multi-URL:** upstream rrProbeNode uses g.link, and rrFlightKey keys on g.link. The scheduled path is integrated with g.probeLinks(), but the new active self-heal path still needs a design decision for opts.URLs (link is empty). A fix must key flights by complete endpoint list and preserve the physical cap of 16 self-heal probes per core, shared queue, one logical verdict, cancellation, monotonic network freeze. Simply parallelizing 3 URLs per reserved queue place could raise physical in-flight probes to 48; do not do that silently. Consider bounded endpoint fanout or an equivalent native queue integration, and distinguish queue wait cancellation from a dead verdict.
- Confirm previous C3/C4 F2 stage budgets and F3 / FinalMask through tests. C5 Windows WSA classification remains a separate follow-up; no Windows deployment in b50.
- Native Apple config checks run actual Swift profile builder, then CLI check (parser + Box.New), including valid generated profiles and rejected old keys. They do not establish on-device behavior or arbitrary imported legacy config compatibility.

Review should return GO / CONDITIONAL GO / NO GO with critical/high/medium/low findings and explicit decision on RR multi-URL. No code changes by reviewer. This is a staged migration, not a release.


## Review #3 disposition — CONDITIONAL GO (GLM)

- F1a: Linux race gate timed out in transport/v2rayxhttp TestPacketUpFailedPostFailsStream (11m57s, run 45991844330). Windows full-tag xhttp passed three times according to the reviewer; rerun Linux, then isolate pure LX.37 vs overlays if reproducible. No IPA before full gate.
- F1b: native Swift harness omitted Library/Network/GroupPresentationSettings.swift; add the actual pinned source, not a stub.
- F2: known upstream timing-dependent TestTransportStage_LX/refused failure. Reviewer reproduced on clean LX.36, clean LX.37 and b49 on Windows. In common/lxtrace/trace_lx.go rootCause(), transport_response can end before the parent transport stage; the current recovered-child filter then returns zero instead of the refused response. Do not change production tracing or suppress the Linux test in this migration. Report upstream with reproduction and ordering evidence; no upstream issue URL confirmed yet.
- F3: reviewed URLTest overlays accepted, preserving selectionWriter, lock order, opt-in passive guard and non-interrupting fallback.
- F4: native RR endpoint queue integration approved, not unbounded fanout: ordered endpoint-list flight identity; reserve and release one physical slot per endpoint under core-wide cap 16; first-success / all-fail single node verdict; queue withdrawal is not a dead verdict; freeze prevents fresh launches. Mandatory endpoint-cap, identity, verdict, withdrawal and freeze tests. Separate review of RR diff before release.
- F5: full Linux race and native profile checks remain required. No release or IPA until gate and separate RR review are green.
