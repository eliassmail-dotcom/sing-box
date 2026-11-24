# iOS adaptive connection reliability — review/QA notes

Scope: iOS only, baseline b39 c211f522. Release gate HOLD until GPT and GLM both approve the implementation. No IPA workflow dispatch on the review branch.

F2 f4e91b653: GLM reports GO; local go vet, dialer race tests, TLS tests passed. Reviewer follow-ups:
- R1: syscall.ECONNREFUSED classification is iOS-specific in scope; Windows WSAECONNREFUSED parity is not part of this package.
- R2: omitting timeout/cancellation penalties for legacy plain TCP IP races is intentional: absence of a timely reply is not a definitive IP refusal.
- R3: check representative generated iOS profiles use tcp_concurrent, domain server and actual resolve dialer (domain_resolver/bootstrap path). Check native VLESS REALITY eligibility.
- R4: run prepare-b38 on an isolated QA checkout and verify that LX35 merge plus FinalMask patch preserves the typed REALITY failure, verified race, warmup hooks and compilation.

F1: one-shot warmup only on iOS after the initial URLTest startup barrier; pending/in-flight URLTest and foreground attempts suppress or cancel it. Fresh successful URLTest TTL 10m; fresh authenticated winner must still be present in current DNS answer. Queue <=8, workers <=2, candidate TCP races <=3/worker. No nested multi-interface fanout in optional warmup. Close winning stream immediately and hold worker until losers close. No VLESS payload, no fake URLTest history, no persistence. If network or selection changes during the wave, abandon it rather than schedule another sweep.

F1 review (abfac6ce5): GLM conditional GO pending B1 compile correction (both nested interface race return paths must return conn, primary bool, error). With that correction applied locally, GLM reports go build ./... OK; dialer/urltest/group/route/TLS race tests PASS; VLESS tests without -race PASS. These are reviewer-reported results, not a developer-side test run.
- W1: the first network change after sealing ends the one-shot coordinator for this Box lifetime; regular URLTest remains responsible for subsequent networks.
- W2: strictFailures denotes the adaptive authenticated REALITY path at the winner recording call; a plain TCP winner must never set winnerAuthenticated.
- W3: a retained URLTest history entry younger than 10 minutes suppresses optional warmup regardless of its result. The standard failed group probe deletes history, so a failed probe with no retained entry does not by itself suppress warmup; pending/in-flight plans still suppress it. Do not interpret warmup as an automatic retry of every failed URLTest.
- Known baseline QA issue: GLM reproduced protocol/vless/encryption -race checkptr failure in sing-vmess NewVisionConn on both c211f522 and F1 with B1 fixed. Record separately from F1/F2; run the encryption tests without -race as well and preserve the race failure in the QA report. Do not disable checkptr globally or claim the entire suite passes.

QA before release GO (unit tests only; no IPA build):
- go vet ./common/dialer/ ./common/urltest/ ./protocol/vless/ ./common/tls/ ./protocol/group/ ./route/
- go test -race -count=1 -ldflags '-checklinkname=0' ./common/dialer/ ./common/urltest/ ./protocol/vless/ ./common/tls/ ./protocol/group/
- go test -race -count=1 -ldflags '-checklinkname=0' -tags 'with_utls with_lx_command with_lx_idle_suspend' ./common/dialer/ ./common/urltest/ ./protocol/vless/ ./common/tls/ ./protocol/group/ ./route/
- Repeat applicable tests on a disposable checkout after prepare-b38; verify workflow preparation assertions and no unintended change to other protocols.
- F3 and final regression matrix to be added before release gate.

Device QA after authorized IPA: home Wi-Fi, office Wi-Fi, LTE, network switch, direct multi-IP and single-IP, Ru chain, White, Gemini, corporate, Smart Three-Tier, XHTTP/FinalMask. Measure peak Network Extension memory, socket/worker cleanup after optional warmup, time to first usable connection, and verify no extra traffic for fresh nodes. No performance claim before measurement.

F1 final GO: GLM verified pushed 04a9de62e; build and affected race suites PASS. F3 review pending.

F3: per-IP direct native VLESS REALITY adaptive record fragmentation, iOS only. The unprepared b39 bool record_fragment cannot distinguish omitted from explicit false; feature is intentionally fail-closed until prepare-b38 applies LX35 pointer semantics plus FinalMask/sniff_guard exclusions. Test prepared and unprepared eligibility separately. Preserve single-distinct-IP behavior. One retry in same candidate, same absolute total budget (<=2.5s), no retry on TCP/auth/config failure or caller cancellation. Minimum residual budget 300ms. Cache only consumed authenticated winners, per outbound/IP/port/epoch, TTL 10m; invalidate observed failed cached mode without erasing a newer concurrent entry. No cache writes by late losers. On transient failure of a previously fragmented cached mode, try plain once with residual budget. No explicit fragment, spoof, FinalMask, detour, transport, or sniff_guard override.

## Integration gate — F1/F2/F3 source review GO

GLM reports F3 758a0f371 build and affected host race suites PASS, including the unprepared configuration gate. F3 W1: invalidating a retained mode after a TLS timeout is intentional: it is an advisory shape preference, not IP failure or proof that a node is dead. F2 timeout classification remains unchanged. W2: source review is not prepared-tree approval.

The isolated QA workflow `.github/workflows/ios-adaptive-prepare-qa.yml` runs on `qa/ios-adaptive-source-758a0f37` only. It runs the existing prepare-b38 script, checks the F1–F3 and LX35/FinalMask hooks, commits the actual merged and patched source tree and pushes it to `qa/ios-adaptive-prepared-758a0f37`. The output is a review snapshot, not an IPA release; **do not run prepare-b38 a second time on that already prepared snapshot**. Record the exact upstream and source SHA in the merge commit. No IPA build, tag/release, Apple project version bump or Windows workflow is performed. The release gate remains HOLD until both reviewers approve the prepared source/test results.

Regression matrix (host QA is not device validation):

| Invariant | Pre-release source/host gate | Remaining validation |
|---|---|---|
| Direct REALITY IP race, F1/F2/F3 | Prepared config gate, authenticated race, real wire shape, dialer/urltest/group/route race suites | Cold/warm field latency and memory on iPhone |
| RU chain / detour | with_lx_chain chain package race tests, detour fragmentation and explicit false tests; source guards preserve existing paths | Real RU first-hop/exit path on Wi-Fi/LTE |
| FinalMask | with_utls prepared FinalMask and REALITY tests, prepared F3 eligibility exclusions | Actual node connectivity |
| XHTTP | with_xhttp transport and option tests; native-only F3 eligibility | Actual XHTTP profile traffic |
| White / Smart three tier | protocol/group priority/failover suite | Generated profile Base -> RU chain -> White ordering and live failover |
| Gemini | route/group/option regression tests; inspect current generated profile and Apple override/builder fixture tests (not executed by host Go workflow) | Actual G-mode, Gemini exit region and NotebookLM |
| iOS start | early RPC guard, shutdown, libbox command socket path tests; no changes to Swift in F1–F3 | Signed installed IPA start, network transitions, memory and widget smoke tests |

Actual Yandex-generated iOS configuration and Apple-only Swift tests must be checked separately; host Go green does not certify routing policies or Network Extension startup. No production credentials or subscription URLs should be printed in CI.

First integration run 45386405829: actual prepare-b38 and all source guards PASS (LX35 f1bac271853eaf13398ce1030c948aebc3aed2e1); push rejected because upstream changed workflow files and GITHUB_TOKEN lacks workflows permission. Tests skipped in this run. The revised QA publishes a source-identical review snapshot with .github/workflows preserved from the source branch, while retaining the exact prepared merge in a Git bundle artifact and testing the exact merge. The snapshot is not an alternate build pipeline. Verify source equivalence outside .github/workflows and record both commit SHAs. If branch push is rejected, the bundle remains the source of truth.

Integration run 45386773368: pinned core submodules initialized successfully; actual build then failed at common/tls/reality_client.go:158 (e.ctx removed in LX35). Fix afa1388091ba00234fe76d0ba5fdd36183092cee: prepare-b38 reconciles exactly the stale fallback call with the handshake ctx; preserves asynchronous rejection and the upstream context-aware HTTP fallback implementation, F2 definitive error, and F3 classification. New QA snapshot branch qa/ios-adaptive-prepared-758a0f37-r2. Old snapshot remains immutable for review. All build/test results pending; HOLD.

### B2 review and full Apple-tag gate

GLM independently confirmed B2 on aa30c68f and locally verified the one-line fix with with_utls. The fix is in prepare-b38 only (afa1388091ba00234fe76d0ba5fdd36183092cee); pre-merge b39 source keeps e.ctx. New prepared snapshot d12ceba514a500939df9ad9df7a004361680b50d; exact merge a56ef789e3a6f139ecd5d5bfdf0a64d66976a88b, artifact 14917881851 in run 45387900148. Prepared source inspection confirms the corrected fallback, typed auth rejection and F3 marker coexist. Require a separate Apple QA gate using the exact merge: dynamically extract all sharedTags and darwinTags, include with_clash_api and the non-macOS with_low_memory tag, compile and race-test on the same xcode-27 runner class as the IPA workflow; then compile Libbox for ios/arm64 and iossimulator/arm64 using the actual build_libbox command. No SFI app build, IPA, version bump, remote tag or publication. Both host/Apple QA and independent GLM review must pass before IPA release gate. The known preexisting VLESS encryption race checkptr issue is not suppressed globally; run that package without race.
