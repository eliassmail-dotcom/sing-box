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

## Stage 10 — UDP Salamander pilot

- Opt-in finalmask_udp list inside V2Ray QUIC or XHTTP HTTP/3 transport; currently only a single salamander entry with password, validated at load. Non-H3 XHTTP rejects it. At this stage additional UDP masks failed explicitly; Gecko is added in Stage 11.
- Independent connected-datagram adapter follows Xray v26.11.9 Salamander salt/BLAKE2b-256/XOR wire format. No syscall bypass, no caller-buffer mutation, bounded 4096-byte wire datagrams and separate read/write locks and scratch buffers. Not authenticated encryption.
- XHTTP keeps carrier classification on the original connection; QUIC guard sees the plaintext datagram and its writes pass through the mask. QUIC socket lifetime is unchanged. Native Hysteria2 obfuscation is unchanged.
- Tests exercise UDP datagram framing and reference-peer interoperability, malformed short packets, invalid settings, compile QUIC/XHTTP paths, and run actual masked and unmasked HTTP/3 stream round trips against an independent in-process reference peer. Full external Xray and iOS resource tests remain pending.

## Stage 11 — UDP Gecko

- Xray-style salamander packetSize (integer or string range, 1–2048 bytes) enables Gecko. Long-header datagrams are fragmented into 2–8 frames with randomized padding; short-header datagrams use ordinary Salamander. Connected-UDP-only implementation, no changes to Hysteria2.
- Out-of-order reassembly, duplicate rejection, 8-second expiry, eight concurrent assemblies, max 4088 bytes per assembled datagram. Lazy expiration, no dedicated timer/goroutine. Limit is per connected peer and intentionally bounded for mobile.
- Uses the pinned upstream wire layout; reference datagram tests cover framing, padding, reassembly, duplicates and bounds. External Xray binary interoperability and resource measurements remain release gates.

## Stage 12 — UDP Noise declarative subset

- One connected-UDP noise mask, standalone or ordered with Salamander/Gecko. Emits static/random/exp datagrams before the first write, or after the configured sliding idle reset interval; no receive-side transform. Supports b/r/rc/rd/t/c/n expression segments. Legacy random length/reset/delay ranges are half-open as in Xray, expression size and random byte-value ranges inclusive. Lua script execution explicitly unsupported.
- Limits: 16 items, 1200 bytes per noise datagram, 8192-byte burst, one second total configured delay, reset at most 86400 seconds. No per-peer map or background goroutine; close and write deadline interrupt delays. Unlike upstream, write errors are propagated rather than ignored.
- Tests cover declaration validation, sequence/reset, expressions, ordering against independent Salamander decoding and cancellation. Real Xray interoperability and device resource measurements remain pending.

## Stage 13 — UDP Header Custom prefix client

- Supports prefix mode with static/random items, capture/reuse and bounded transforms through the existing header compiler. Client header sizing is validated before dialing; server expressions can use previously captured client bytes. Receive metadata expressions are rejected, matching Xray's address-free receive evaluator.
- Per-connected-peer state has a five-second TTL. Failed matches never commit captures; malformed packets are dropped. Header lengths limited to 512 bytes per direction and 64 items total. No background goroutines.
- Ordered composition with Noise and Salamander/Gecko; one instance per mask, at most three. Standalone mode was initially unsupported; see Stage 14. External Xray process interoperability, full chain tests and mobile measurements remain gates.

## Stage 14 — UDP Header Custom standalone client

- Separate request/reply datagrams before payload, with five-second session TTL and repeat handshake after expiry. Reuses existing item validation and expression evaluator. No prefix applied to application payload.
- Single lazy read pump per connected socket; bounded eight-datagram payload queue drops overflow instead of blocking the handshake. Matching replies consumed internally. Close and write deadline interrupt handshake; recoverable read deadlines apply to the wrapper queue. Failure terminates the connection.
- Standalone mask must be used alone until composition is validated. Nonempty request/reply required. Tests cover repeated exchange, concurrent read/write, deadline, queue saturation and configuration guards. External Xray interoperability, full IPA and resource measurements remain pending.

## Stage 15 — UDP Sudoku

- Classic hint encoding in both directions, matching the pinned Xray UDP codec, resetting table rotation and padding per datagram. Reuses immutable compiled tables and shared clue index from TCP Sudoku. No new background goroutine.
- Mobile pilot limits input to 2048 bytes and encoded wire datagrams to 18433 bytes (maximum expansion 9x plus final pad). Oversized and malformed incoming datagrams are discarded; short output buffers drop datagrams as upstream does. Write errors are explicit.
- Only standalone Sudoku mask is allowed initially: other UDP wrappers currently have smaller wire budgets. Large encoded packets may undergo IP fragmentation or be dropped by the network; actual path MTU and device resource tests are mandatory before use. Tests cover reference codec both directions, table reset, maximum padding, invalid hints, oversize, deadlines, and configuration guards.

## Stage 16 — mKCP Legacy UDP masks

- Implements Xray v26.11.9 original FNV/length/XOR framing, AES-128-GCM with SHA-256-derived key, and DNS/DTLS/SRTP/uTP/WeChat/WireGuard header variants. This is not the mKCP transport.
- Connected datagrams, bounded 4096-byte wire frames, independent locks and scratch buffers, no background goroutines. Invalid original/AES frames are dropped; fixed headers are stripped without validation as upstream. DNS accepts ordinary nonempty labels only.
- Standalone mask only until combination and overhead budgets are verified. Tests include header vectors, counter progression, original and AES reference decoding, corrupt packet rejection and size guards. Full external Xray interoperability and device measurements remain pending.

## Stage 17 — XDNS UDP/TXT pilot

- One explicit literal-IP UDP resolver, one ASCII domain, TXT queries and answers only. EDNS0 2048–4096 required for QUIC; TCP/DoH, A/AAAA/CNAME, multiple resolvers and mask composition rejected. Uses existing configured dialer to the resolver rather than the original QUIC address. XHTTP QUIC sniff shaping is skipped only for this replacement carrier.
- Upstream-compatible client ID, query nonce, base32 domain labels, fragmentation and TXT response framing; pending query ring (256), reply queue (8), two lazy workers per connection. Polling backs off 500ms–10s. Replies match outstanding ID and question. No external resolver or production network is contacted by tests.
- Local reference test checks fragmented writes and a full-size TXT reply. External Xray, loss/throughput and mobile resource tests remain mandatory. This is not full XDNS parity.

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

## Stage 18 — XDNS record types

A, AAAA, CNAME and TXT are accepted, with a random configured type chosen per datagram, correct client-ID type bits and matching pending query type. Indexed responses tolerate reordering and reject missing or duplicate records; A/AAAA permit only bounded zero padding. The default remains TXT. A and AAAA response capacity is substantially smaller than TXT; A-only cannot carry a normal QUIC Initial response at the supported EDNS limit. Codec tests are not proof that all query-type combinations support a working QUIC session. TCP/DoH and multiple resolvers remain unsupported.

## Stage 19 — XDNS TCP carrier

Single explicit literal-IP UDP or TCP resolver, chosen through the same outbound dialer. TCP uses RFC 1035 two-byte big-endian DNS length framing, handles fragmented/coalesced stream reads and partial writes, caps frames at 4096 bytes, closes on framing/stream errors, and exposes UDP address semantics to QUIC. Existing XDNS workers/queues are reused. No transparent TCP reconnect: failed carrier terminates and the outer transport must redial. Tests cover framing, malformed lengths, default UDP path and a real local TCP XDNS exchange. DoH and multi-resolver failover remain unsupported. External Xray and actual QUIC-over-XDNS TCP interoperability remain unverified.

## Stage 20 — XDNS DoH pilot

HTTPS POST application/dns-message using the outbound dialer, one literal-IP resolver URL with explicit path, optional verified TLS serverName and HTTP/1.1 or HTTP/2 ALPN. No redirects, proxy environment, insecure TLS, HTTP/3 or Xray-specific TLS fingerprint options. Four workers maximum, queues of 16, five-second request timeout, 4096-byte DNS reply limit and bounded response headers; HTTP failures treated as datagram loss, HTTP 429 triggers a five-second cooldown. Carrier lifetime owns cancellation independently of the QUIC handshake. Full Xray interoperability, multi-resolver failover, HTTPS hostname bootstrap and actual QUIC-over-DoH remain pending.

## Stage 21 — XDNS multiple resolvers

Accepts at most three distinct UDP/TCP/DoH addresses (multiple addresses per resolver entry or separate entries), with aggregate DoH worker budget four. Uses the configured outbound dialer; per-socket TCP framing happens before multiplexing. Selection is rotating least-unanswered-query count; a matching DNS response resets that resolver's count. Hard read/write failure retires the socket for this session, while silent loss shifts traffic toward responsive peers. No transparent recreation of retired carriers until outer reconnect. Bounded receive queue of eight, one reader per live carrier, stable virtual UDP address; no additional retry loop. Tests cover selection, initial failure, retirement and budget. External Xray interoperability and real iOS resource measurements remain pending.

## Stage 22 — XDNS DoH HTTP/3

Explicit exclusive tlsConfig.alpn=["h3"] selects HTTP/3 in with_quic builds; other builds reject it during config validation. Uses existing quic-go and outbound dialer, verified TLS, one pooled HTTP/3 transport, same worker/queue/request limits. No 0-RTT requests deliberately enabled, no insecure verification or HTTP downgrade. UDP carrier closes on QUIC failure/end; closing DoH cancels requests and closes HTTP/3 transport. QUIC receive windows bounded for mobile pilot. Local real HTTP/3 resolver tests verify protocol, trust and shutdown. Xray-specific quicConfig overrides and full external Xray interoperability remain pending.

## Stage 23 — XICMP client pilot

Single selected literal IPv4/IPv6 endpoint per session, optional list up to four IPs. Uses explicit direct dialer ICMP socket capability and existing ICMPControl; resolver wrappers only forward that capability, detours fail closed. Unix raw and datagram socket paths, no privilege escalation or automatic raw fallback. Windows/other builds explicitly reject at dial until supported. No network namespace support in this pilot. Client ID, echo type/sequence, peer filtering, own echo rejection and bounded buffers follow Xray framing. No additional worker goroutines. Tests use local reference sockets; raw/datagram OS permissions, real Xray server and iOS Network Extension behavior remain unverified.

## Stage 24 — Realm client pilot

Reuses sing-quic hysteria2/realm Discover, ControlClient, Punch and metadata codec. Explicit realm://token@literal-IP/id HTTPS endpoint, verified TLS (optional serverName), up to four literal STUN servers, single selected IP family (v4/v6 or first STUN family in dual), at most four returned peers. Both HTTP and UDP use the configured dialer; no system DNS lookup or automatic port mapping. Overall setup deadline 20s, HTTP response body 16 KiB, close-on-cancel and failure, same UDP socket retained for data. Peer source filtered, late punch packets dropped. No persistent worker introduced by this adapter. Port mapping, full dual-family race, hostname resolution, combinations and external Xray tests remain pending.

## Stage 25 — UDP Hop client pilot

Supports intervalLocal, intervalRemote, perConnRemote and comma-separated combinations using the configured outbound dialer. Literal endpoint required; explicit remote IP prefixes restricted to /24 IPv4 or /120 IPv6 and narrower, at most eight prefixes and 256 ports. Remote-only hopping keeps one socket, local hopping opens a replacement before rotating and retains one previous socket for a single interval. No timer/worker for per-connection-only selection. Bounded eight-packet queue and two active read pumps, cancelable dial with two-second budget, wrapper-level read deadline, write deadline carried to new sockets. Source filtered against current/previous selected endpoints. Old path retained on dial failure. No unbounded queue or fallback direct dial. Composition, real server migration/NAT and iOS performance remain unverified.

## Stage 26 — QUIC Params and BBR pilot

Opt-in quic_params for V2Ray QUIC and XHTTP HTTP/3. Supports receive windows, idle timeout, keepalive, PMTU disable, ChromeParrot disable, incoming stream limit and BBR conservative/standard/aggressive using existing sing-quic congestion_meta2. Explicit conflicts with ChromeParrot's pinned parameters rejected. Defaults unchanged when absent. Windows bounded to 16 MiB per setting, streams to 256, time limits follow Xray. BBR installed at QUIC dial return (not Initial handshake). Reno, Brutal negotiation, force-brutal, GSO/stateless-reset switches and XDNS quicConfig remain pending. No global env mutation or debug toggles. Client-side only; server, real Xray and iOS performance verification pending.

## Stage 27 — QUIC Reno / force-brutal

Explicit reno retains native Reno in pinned quic-go mod.14 (NewCubicSender called with reno=true). force-brutal uses existing sing-quic BrutalSender; optional loss compensation disable suppresses only ACK-rate adaptation. Xray-style bandwidth strings are bits/s with binary multipliers, bounded to 64 KiB/s–128 MiB/s. Plain negotiated brutal and brutalDown are rejected for generic QUIC/XHTTP: Xray only negotiates them in Hysteria2 and the existing Hysteria2 implementation is unchanged. No global debug variables. No parameter means the former default. Tests verify mapping, bounds and selection of the actual sender type; sustained throughput, loss testing and external server interoperability remain pending.

## Stage 28 — GSO and client stateless reset

The pinned SagerNet quic-go mod.14 exposes no per-transport GSO-only switch. Opt-in disableGSO hides syscall/replaceable capabilities from QUIC after all masks and sniff-guard wrappers, using ordinary connected UDP reads/writes. This also disables ECN/batch syscalls and explicitly disables PMTU discovery; no process-wide environment or dependency fork changes. disableStatelessReset is accepted because single-use client DialConn/DialEarlyConn already create a Transport with nil StatelessResetKey (no outbound reset generation); inbound valid peer resets are unchanged. Xray's reset toggle is relevant to server-side transports. Defaults unchanged; test covers carrier capabilities, deadline delegation, config mapping, and actual XHTTP/3 exchange. A GSO-only optimization switch would require a quic-go change. No device performance claims.

## Stage 29 — XDNS HTTPS hostname bootstrap and QUIC parameters

HTTPS resolver URL may use an ASCII hostname when the resolver entry supplies explicit bootstrapIP. The configured outbound dialer receives the literal address; HTTP authority and default TLS SNI remain the URL hostname. No system DNS fallback or implicit recursive resolution. Plain UDP/TCP still require IP literals. Optional Xray-shaped quicConfig uses the existing client QUIC compiler for HTTP/3 only, with 2 MiB receive-window ceilings and no incoming bidirectional streams. Applies congestion control and per-node basic UDP fallback to the inner QUIC connection; no settings alter the outer connection. Default inner QUIC settings unchanged. Explicit bootstrapIP is an LX extension, not a claim of complete Xray config parity. Multi-domain XDNS, automatic hostname bootstrap and extended TLS options remain pending.

## Stage 30 — XDNS multi-domain

Up to four names across up to four domain groups, each with independent type set, EDNS and encoding limits. Select one domain per datagram/poll, all fragments use that domain, pending entries retain the chosen codec for response validation. Duplicate and nested suffixes rejected to avoid ambiguous DNS routing. Single-domain defaults, resolver budgets and wire layout unchanged. Fragment ID increments only for fragmented datagrams (matches upstream). No extra workers or queues. All configured names must point to the same XDNS server/session state. External Xray and iOS resource tests remain pending.
