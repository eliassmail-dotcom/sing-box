# b50 / LX.37 — Peer Review #4: RR multi-URL endpoint reservations

Candidate source gate commit (verified against Actions API): 92c0d3ad4a7cfea0ef96f53cc7e0a7e77a886536.
Base peer review #3 packet commit: 4eb4646cab28fd7738346a881e5dfc2b0418de71.
Compare: https://github.com/eliassmail-dotcom/sing-box/compare/4eb4646...92c0d3ad4a7cfea0ef96f53cc7e0a7e77a886536
Gate: https://github.com/eliassmail-dotcom/sing-box/actions/runs/46003950620 — completed SUCCESS at 2026-11-27 13:12 UTC, exact candidate SHA above.
Upstream trace timing defect: https://github.com/Leadaxe/sing-box-lx/issues/89; no trace source or tests changed.
Original XHTTP rerun: https://github.com/eliassmail-dotcom/sing-box/actions/runs/45991844330 — vet/race step PASS, XHTTP 4.077s; old Swift harness failed as expected on the old immutable SHA. Diagnostic candidate: run 46004240386, 20 isolated repetitions + 3 package repetitions PASS; pure upstream tag derivation corrected in 271f704b38ea385ac8ddfdc9ea93c741b8d6e08b, new comparison run 46004383444: both pure LX.37 and candidate completed SUCCESS (20 isolated repetitions plus 3 full package repetitions, all under race). Initial hang not reproduced.

## Review scope

Compare each new full-source overlay under migration/b50/resolved/protocol/group/ against upstream LX.37 (92041d1a1bed6633a153a63d37ccc954f66c2d61), not the b49 file tree. The preflight verifies exact upstream blobs before application and gofmt. RR files: urltest_rr_queue_lx.go, urltest_rr_heal_lx.go, urltest_rr_track_lx.go, new urltest_rr_multi_b50_test.go. Also inspect check-generated-profiles.sh and the exact source gate YAML. No iOS build or release is authorized by this packet.

1. Physical reservation: each logical flight needs k endpoint places (max k=3 validated by existing config). Initial/candidate batches contain floor(U/k) whole nodes; decisive parts contain floor(U/k)-1 nodes plus a control-after reservation. Verify every return path including skipped launch, no leaf, no outbound, queue wait cancellation, early success, timeout, and settle.
2. A new deduplicated flight owns the reservation, not its first waiter. Joining or withdrawing askers return their unused reservation; each endpoint releases a place only after URLTest actually returns. Late/uncooperative cancellation retains the physical place; logical first-success still returns immediately. Verify no negative count, no leak and no physical fanout beyond 16 active self-heal endpoints. Scheduled probing is outside the upstream self-heal queue.
3. Stable ordered endpoint list JSON encoding replaces the former single link identity (field name retained for compatibility with existing unit fixtures). The exact leaf used for the flight is resolved once and passed to the probe; dedup only identical lists and leaf. Verify stale-flight lower-bound behavior, decisive alone exception, and nested leaf attribution.
4. Use existing probeURLs for first-success/all-fail; one rrProbe and one logical outcome per caller; cancellation from queue wait is not a miss. Verify no change to node-level probeAnswered/poll counters and dead-strike rules.
5. Freeze cancels rounds as upstream, and explicitly cancels waiting/active life contexts. Launch callbacks after cancellation release instead of starting; late miss records require valid epoch. Verify grant/freeze races, lock order, no new work during freeze.
6. The focused RR race step of 46003950620 passed. Six focused tests cover endpoint identity, any-success/all-fail, round cap/freeze, concurrent identical vs reordered flight, queue cancellation/life freeze, physical reservations during delayed cancellation. Existing full RR suite must pass under race.
7. Swift harness compiles real pinned Apple profile, presentation and outbound models. On Linux a declarations-only Libbox bridge traps if any UI method is invoked; actual generated JSON is checked by native merged CLI (parser/Box.New). No behavior of the core is mocked. Verify the generated/rejected profile checks, and flag any gap.

## Verdict requested

GO / CONDITIONAL GO / NO GO. Independently review the RR integration diff, in particular reservations for decisive parts and the cancellation/freeze boundaries. Report findings by severity. Do not merge, tag, or publish an IPA during review. Full green gate + independent GO required before next release stage.

## Final verified gate result (2026-11-27)

- Source reconstruction, pin validation, full-feature Linux build: PASS.
- Focused race suite: 6/6 PASS; protocol/group 1.828s.
- Full vet/race integration: PASS; protocol/group 26.387s, XHTTP 4.426s, experimental/libbox 2.948s; all remaining required packages and VLESS encryption PASS.
- Native Swift-generated profiles: 4/4 accepted; removed idle_timeout and strip profiles rejected with expected diagnostics. Trap-only Linux Libbox UI bridge never invoked.
- XHTTP diagnostic matrix (46004383444): both clean upstream and candidate SUCCESS; no reproduced hang.
- Independent GLM peer review #4: GO (2026-11-27); iOS build authorized.

## Independent reviewer disposition (GLM #4)

GO. Reservation ownership, physical cap, ordered endpoint identity, one logical verdict, withdrawal, freeze and native profile gate accepted. Local Windows focused tests 6/6 PASS. Reviewer reproduced `TestRRAlgo_10_secondSoftSignShifts` on pure LX.37 on Windows; not a b50 regression. Linux full group suite passed. Report separately within upstream issue #89 discussion, without modifying the tests. The legacy queue.probe helper remains for fixtures; optional future defensive bound deferred because URLs are validated to <=3 and the reviewed source must remain byte-for-byte unchanged. The full SHA is verified against Actions run 46003950620; the compare link uses the verified head and unique base prefix.

Final iOS build workflow: .github/workflows/b50-ios-ipa.yml, initial workflow commit 30f1aa2555746b39e9389c8734084ac87ff8f649. Checkout is pinned to the reviewed gate SHA and Apple eae7921330d0e154b20a29db7c6051b9eab2a6bf; no post-review production code change.

## Darwin IPA acceptance follow-up

- Initial IPA run 46008149198 compiled the reviewed core and passed the production-tag regression suite, then failed the additional untagged group test `TestRRUDP_poolSkipsDeadAndQuarantined` (expected six opens through b, observed four; a/c remained zero).
- Diagnostic run 46011990983 reproduced the same failure on the pure upstream LX.37 (3/100) and on the reviewed b50 (4/100). The original test assumes the pool remains static, but the first UDP pick may start a background repair and install candidate d during the six opens. Holding the fixture's background round through the assertions (existing holdRound/dropRound helpers) yielded 100/100 passes on each source.
- Acceptance workflow revision 50244466380951e8dedd1f8c892771a220e1ad91: apply the two-line fixture-only fix to the exact upstream test blob 667247dc318979b37943c5127839080e6b796a2f, repeat the target test 100 times, execute all original regression gates, then restore the original test blob and verify the reviewed core tree before building Libbox. No production source or acceptance assertion changed. Initial workflow edit f1719f35 was invalid YAML, superseded without running jobs.
- New IPA gate: https://github.com/eliassmail-dotcom/sing-box/actions/runs/46012373148. Acceptance remains pending until successful completion; device VPN smoke test is separate.
