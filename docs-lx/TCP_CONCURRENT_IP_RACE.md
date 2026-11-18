# LX experimental TCP IP racing (2026-11-18)

Status: **experimental, isolated in `feature/lx-ip-race`**. No change to
`Leadaxe/sing-box-lx` release tags, production Yandex profiles, or signed IPA.

## Motivation and reproduced case

The UK VLESS hostname `en-n1.gsupport.support` had **nine IPv4 answers**.
The Wi-Fi diagnostic with nine otherwise identical direct VLESS outbounds
reported a successful URLTest for **164.37.109.246** (`IP06`) at 149 ms,
and the user then demonstrated real traffic on that path. The other eight
addresses did not yield successful URLTest entries in that snapshot. This
suggests, but does not alone prove, that connection selection is the cause of
the normal hostname's failure.

Upstream `sing/common/network/multi.go` races IPv4 against IPv6 but falls
back to serial dialing when only one IP family is present. Several dead IPv4
addresses can therefore consume the URLTest or application deadline before
the usable address is reached.

## Implementation

The code is an adapted, intentionally limited port of the *approach* used by
[MiChongs/sing-box](https://github.com/MiChongs/sing-box/blob/xiaobaf14g-testing/common/dialer/concurrent.go)
and [Xray-core](https://github.com/XTLS/Xray-core/blob/main/transport/internet/happy_eyeballs.go).

- New per-outbound dialer setting: `"tcp_concurrent": true`.
- Default `false`; existing profiles preserve existing behavior.
- Applies only to **TCP connections from a direct socket dialer** to a
  **hostname with multiple resolved IPs**. Enabling it together with
  `detour` or `tcp_fast_open` is rejected explicitly to avoid unsafe
  guesses about chain/TFO semantics.
- Races up to **four** candidate sockets, starting one more every **75 ms**.
  If an attempt fails, the next candidate starts immediately.
- Returns the first established TCP socket; cancels and closes all losers,
  including sockets that appear after cancellation.
- Keeps the last winning IP in that outbound's memory for **10 minutes**.
  The winner gets a **20–250 ms** head start, determined by recent TCP
  connection duration. Failed IPs are deprioritized for **one minute**.
  Candidates must always appear in the latest DNS reply.
- **VLESS `InterfaceUpdated`** clears both caches on Wi-Fi/cellular
  network changes.
- DNS selection, interface binding, TLS SNI, REALITY public key, short ID,
  VLESS flow, UDP handling and original network rules remain unchanged.
  The IP is substituted only at the TCP socket destination stage.

## Example

Add the field to an **original direct VLESS node**, not its `Ru 🔗`
second-hop clone. In a JSON outbound containing the existing UUID,
hostname, and REALITY settings, the additional property is:

```json
"tcp_concurrent": true
```

Do **not** enable this in the currently installed iOS LX/IPA from
`Leadaxe/sing-box-lx v1.14.4-lx.33`: it does not contain the new option.
A patched LX binary/Libbox build is required before using the new setting.
The 9-IP diagnostic Yandex profile and normal subscriptions remain usable
without it.

## Verification

CI builds the native LX CLI and runs the dialer, option and VLESS test suites
under the Go race detector. Specific tests include sixth-IP selection,
preference of the last winner, DNS membership, all-address failure, caller
cancellation, JSON option parsing and interface-change invalidation.

No live Wi-Fi runtime test has yet been performed against this patched
binary. This race chooses a successful **TCP connection**, not a successful
REALITY/VLESS session: a TCP-accepting endpoint that fails REALITY could
still win. If that occurs, a higher-level REALITY-aware race would be a
separate feature.

The experiment is not an upstream or Leadaxe release, and has not been
deployed into an IPA.
