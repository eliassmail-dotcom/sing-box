# SFI LX++ v1.14.9 build 40 — RELEASE GO

Final disposition: **GO / GO**, 2026-11-24. Independent GLM review and developer-side CI verification complete. The original HOLD-labeled GitHub Actions artifact is approved for delivery unchanged. Its historical name and embedded manifest deliveryStatus record the state at packaging; this release record supersedes that status. No rebuild, byte modification, signing or deployment.

- Prepared core: d12ceba514a500939df9ad9df7a004361680b50d
- Prepared tree: 2631290510fe58a83b76feb778a72d2b15fe0f87
- Apple client: df5c02ca040994dca6d40884789c65bc384badf1
- Build workflow commit: 886df62bf58fefd2e13bae5a77181398af2b1f57
- [Host integration QA PASS](https://github.com/eliassmail-dotcom/sing-box/actions/runs/45387900148)
- [Full Apple QA PASS](https://github.com/eliassmail-dotcom/sing-box/actions/runs/45388347038)
- [IPA build and simulator XCTest PASS](https://github.com/eliassmail-dotcom/sing-box/actions/runs/45390446795)
- [Approved unsigned IPA (original ZIP)](https://github.com/eliassmail-dotcom/sing-box/actions/runs/45390446795/artifacts/14920587674)

## SHA-256 verified from downloaded bytes

IPA (57,278,895 bytes): `d82bdaaa1a21decb91e1c9d7a88ea69df115ccd5942063cbc482fa04f365a118`

Original GitHub ZIP (57,167,050 bytes): `99746437060a8341b842e229b1133d5dd228f9b362ef2a6ca91bfdc655a9d303` (matches GitHub digest).

## Changes

- F1: authenticated IP cache warmup on iOS; bounded one-shot, no persistent cache, no extra VLESS payload, skips fresh/in-flight paths.
- F2: adaptive verified IP race, bounded TCP/TLS budgets, generation fencing and definitive failure classification.
- F3: adaptive REALITY record fragmentation after prepare-b38; one same-IP retry within original budget; authenticated winner cache. Native direct hostname multi-IP VLESS REALITY with tcp_concurrent, no explicit fragment/record_fragment/FinalMask, detour, XHTTP or sniff_guard override. Single-IP unchanged. Cache preference invalidates on failed observed mode.
- LX.35 + FinalMask retained; B2 integration correction in prepare-b38.
- Smart three-tier Base -> RU chain -> White retained.

## Artifact acceptance

Downloaded IPA archive integrity passed. Embedded LXBuildManifest.json matches the prepared commit/tree and pinned Apple client. Main application and six embedded extensions: 1.14.9 / 40. Mach-O Library.framework/Library contains Go build tags (32 including ios) matching prepared build_libbox and iOS low-memory tag; GOOS=ios, GOARCH=arm64. Verified embedded symbols: F1 authenticatedIPWarmup, IPWarmupCoordinator; F2 dialVerifiedCandidateLx, dialAtGeneration; F3 AdaptiveRecordFragment, dialAdaptiveFragmentCandidateLx, recordRaceWinnerWithFragment. No LC_CODE_SIGNATURE in app, framework or six extension executables; no embedded.mobileprovision or _CodeSignature/CodeResources. User signs with GBox.

Known baseline: protocol/vless/encryption -race checkptr failure in sing-vmess reproducible on c211f522; encryption non-race tests pass. Real-device VPN startup, network transitions, connectivity and NE memory/latency measurements remain field acceptance, not claimed by simulator/host QA. No Windows changes.
