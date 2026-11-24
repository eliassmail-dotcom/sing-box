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
