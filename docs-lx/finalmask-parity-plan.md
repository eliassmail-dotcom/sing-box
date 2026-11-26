# FinalMask parity — staged migration

Baseline: prepared/b41-lx36-45688648290-1 (111b2e50a2a065266e14fd4d22827dea501d424f), successful b41 run 45688648290. b42 is independent.

Reference: Xray-core v26.11.9, transport/internet/finalmask/fragment/conn.go and config.proto. Xray uses MPL-2.0; sing-box uses GPL-3.0-or-later. The first change is a behavior-compatible extension of the existing LX implementation; no upstream source file has been vendored. For subsequent ports retain provenance, notices and applicable license terms, and review MPL section 3.3 before distributing combined code.

## Stage 1 — existing TLS record fragmentation

- Existing finalmask_fragment remains opt-in, tlshello only.
- Added optional max_split (integer or range encoded as a string). Omission or zero preserves unlimited splitting. A nonzero cap leaves the remaining payload in the last TLS record, preserving the original handshake and trailing bytes.
- No change to default, IP Race, chain, or adaptive fragment selection. The existing mutually exclusive fragment selection is retained.
- New regression tests cover range, cap, omission, invalid input and payload integrity. CI must pass before release.

## Stage 2 — ordered length and delay ranges
- lengths and delays arrays override their scalar values, with repeat-last semantics; only one zero delay range uses the merged-write path.
- Explicit LX resource safeguards: up to 256 length/delay ranges, nonzero lengths only, at most 5000 ms worst-case total delay per ClientHello, rejected before writing. These limits are intentionally stricter than Xray.
- Delay waits are interrupted by wrapper Close and write deadline updates; tests exercise both. Inherited deadlines set directly on an underlying connection before wrapping are not observable by the wrapper. Actual TLS cancellation still requires real-stack tests.
- The raw TCP write-index modes are now covered by the separate Stage 3 pilot. Numeric JSON ranges, upstream mask ordering and other masks remain unsupported. No generator changes yet.

## Stage 3 — raw TCP transport pilot

- New common/finalmask TCPFragment connection wrapper, configured on a plain VLESS outbound using finalmask_tcp_fragment. Empty packets selects all nonempty writes; N or N-M selects one-based write indices. TLS and other transports/flow are explicitly rejected for this field.
- Reuses length/delay sequences and max_split. Uses serialized writes, short-write reporting, close/deadline-aware waits, and rejects before emitting bytes if conservative segment or delay budgets would be exceeded (16384 writes or 5 seconds per input Write). No per-segment buffering.
- Wraps the connected stream in both VLESS dial and packet paths, before VLESS encryption, without wrapping the dialer or altering its IP Race interfaces. No claim of physical packet boundaries (TCP or detours may coalesce writes).
- No generic dialer integration yet; TCP masks over TLS, other transports, and other protocols need a separately reviewed insertion point and interoperability tests. No production or generator changes.

## Stage 4 — TCP header-custom static/random client pilot

- Supports Xray client/server round ordering, static byte array/string/hex/base64 packets, random bytes, random value ranges, and sending delays. A matching server is required.
- Opt-in finalmask_tcp_header on plain VLESS. Eager bounded exchange after dialing, before encryption and payload; context cancellation closes failed connections. Existing dialer interfaces are untouched.
- Initially rejected capture/reuse/transform and still rejects transforms and error sequences, simultaneous legacy fragment+header fields, TLS/REALITY and other transports. These are not silently ignored. Limits: 16 KiB total header, 256 items/rounds and five-second handshake.
- Tests use a manual reference peer, not an actual Xray binary; upstream interoperability is still a release gate.

## Stage 5 — ordered TCP mask chain pilot

- finalmask_tcp accepts Xray-style ordered entries (type/settings) for fragment and header-custom; the first entry is outermost, constructed in reverse as Xray does. Tests distinguish which bytes a first-write fragment actually sees.
- Supports numeric and string fragment range forms, maxSplit and legacy max_split aliases (not simultaneously), strict rejection of unknown settings. Existing single-mask fields continue unchanged and cannot be combined with the list.
- Limited to plain VLESS, at most one instance of each mask to avoid multiplicative write budgets. Header exchange remains eager; no upstream binary interop claim. Unsupported masks fail explicitly.
- Both VLESS dial paths apply the ordered chain before protocol encryption. A failure closes the connection, including previously applied wrappers.

## Stage 6 — TCP header capture/reuse

- Capture static or random nonempty bytes and reuse earlier values on either side of the same handshake. Validate the variable references in actual alternating client/server order before dialing.
- Variables are per-handshake, never shared across connections; received reuse values must match the captured value. Byte budget includes repeated values, and variable names are limited to 64 characters.
- Transform expressions were initially rejected; server error sequences remain rejected. Cross-connection state is intentionally not implemented; Xray evaluator and binary interop remain separate gates.

## Stage 7 — bounded TCP header transforms

- Typed expression compiler for the pinned Xray vocabulary: concat/slice/pad/truncate, integer packing, xor16/xor32, checked arithmetic and bitwise operations, nested expressions, captured variables and numeric address metadata. Fixed output widths are validated before dialing.
- Limits: 256 expression nodes across a header, depth 12, 64 args per expression, 16 KiB output, 256 KiB cumulative intermediate byte work. Slice/pad/truncate lengths must be literal bounded u64 values (matching Xray receive sizing); metadata must be present on the actual connection. Runtime overflows fail closed.
- This is a behavior-based implementation, not upstream code vendoring. Interop against actual Xray remains pending; server error sequences and additional transports/masks remain out of scope.

## Stage 8 — TCP Sudoku / filter disposition

- Xray filter is a server-side listener/source filter; its client wrap is a no-op. No client filtering was added; the list compiler still rejects unsupported filter entries.
- Ported the Xray v26.11.9 Sudoku table, codec and packed-stream algorithms under MPL-2.0. Client uplink is classic Sudoku and downlink is packed. See common/finalmask/sudoku/UPSTREAM.md for provenance and adaptations.
- Shared immutable clue-group index; no unbounded password-keyed cache. Per-outbound tables share base clue arrays; 4 KiB plaintext write chunks and read chunks, up to eight configured tables, padding 0-100. One sudoku entry is supported in the ordered plain VLESS TCP chain.
- Tests cover independent reference vectors/round-trip, rotation, padding, large streams, and config rejection. Real Xray executable interoperability and mobile memory measurements remain release gates. UDP Sudoku and TLS/REALITY integration are not implemented.

## Stage 9 — XMC client port

- Ported original Xray XMC sources with MPL-2.0 notices, using local JSON config and a test-only upstream server peer. Ordered TCP list accepts xmc, limited to one per type and plain VLESS.
- Uses pinned RSA derivation, login/profile checks, CFB8 and packet/padding state machine. No auto-generated or network-fetched profiles. At most eight profiles, bounded profile fields, password and hostname. Failed client handshake becomes terminal and closes the connection.
- Upstream tests run in a dedicated CI step, in addition to LX integration tests. Actual external Xray process interoperability and CPU/memory on iOS remain release gates.

## Remaining scope (not implemented)

1. Verify pinned upstream parser, all fragment options, mask ordering and error semantics. Finish numeric write ranges and raw transport integration; verify full-stack cancellation and resource tests. Document deliberate divergences from Xray (including zero-length TLS records and incomplete initial writes).
2. Establish a shared transport-layer mask interface, audit TCP/UDP insertion points and detour handling. Do not layer masks twice or move TLS wrapping across the wrong hop.
3. Evaluate other TCP and UDP mask implementations, and QUIC parameters against actual library capabilities; port individual supported masks with upstream interoperability tests, licensing notices and explicit rejection of unsupported options.
4. Update generator import only after core contracts stabilize; add fixture-based checks and backward compatibility for finalmask=true.
5. Compare Xray and LX with the same endpoint and profiles. Include cancellation, short writes, concurrency, memory/CPU and iOS Network Extension constraints. No shipping until regression and real-device checks pass.

References:
- https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/finalmask/fragment/conn.go
- https://github.com/XTLS/Xray-core/blob/v26.11.9/transport/internet/finalmask/fragment/config.proto
- https://github.com/XTLS/Xray-core/blob/v26.11.9/LICENSE
