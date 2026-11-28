# YC macOS Native TUN — Intel Ventura

Status: experimental integration; not a production VPN release.

## Architectural decision

Use the LX desktop core with its existing `lxd` LaunchDaemon and native utun,
rather than a Network Extension. The iOS signing pipeline and Yandex Cloud
Function are independent and unchanged. Use the existing authenticated daemon
protocol, not a new arbitrary privileged command runner.

- Deployment target: macOS 13.0, Intel x86_64 first.
- Core baseline: verified b54 desktop source
  `2909685cb3d1456cc946b1e38cf38c4b4905fab0`, logical-provider delta
  `048ec0280668bf2c311bc36888862273c3da429c`.
- First UI compatibility candidate: upstream Leadaxe/singbox-launcher v2.4.5,
  unmodified and SHA-256 verified. This is NOT a claim of YC UI parity.
- Privileged installation: the existing protected root-owned copy and launchd
  service; local TLS + one-time enrollment, never plain unauthenticated dev mode.
  Keep SIP and Gatekeeper enabled. Do not enable --allow-unsafe-exec.

## Full YC profile delivery

The upstream launcher's ordinary sing-box subscription import is NOT suitable:
it intentionally ignores route, dns, inbounds and experimental and regenerates
configuration. See its pinned core/config/subscription/singbox_import.go.
Do not treat a successful node import as configuration parity.

The existing LXD POST /admin/apply accepts the full JSON bytes, validates with
the same daemon binary, and records the last-good profile with rollback on a
failed startup. Build the YC external-profile path around that contract:
- Preserve all route/DNS/endpoint/outbound/SRS/LX semantics. Do not reconstruct
  the JSON from URI nodes. Verify active_sha256 and report apply failures.
- Preserve `experimental.clash_api.default_mode` and its `clash_mode`
  routing/DNS dependencies (notably G-Smart). The launcher standard daemon
  preparation strips Clash API and gates unsupported keys, so do not call
  that transformation on YC profiles blindly. Keep the loopback API local,
  provision a per-install random secret for the UI, and resolve controller
  port conflicts without changing mode semantics. Resolve the cache_file
  path into the daemon's protected state directory if needed. Record any
  platform-only changes and hash the actual applied bytes.
- Keep the input TUN tag (iphone-tun) unless all references are migrated.
  The tag is not an OS binding. Check auto_route, auto_detect_interface,
  and native macOS DNS handling. Reject iOS-only localdev mode for this target.
- Use the daemon's existing pinned mTLS protocol; do not expose a LAN debug API.
  If temporarily testing via the launcher's authenticated localhost API, use
  /daemon/raw/rest with body_base64, a random bearer token, no proxy/redirect,
  and inspect the nested daemon status and active hash.
- Do not automatically enable shell hooks or root commands. If native DNS
  cleanup is insufficient, implement and test a narrowly scoped, idempotent
  recovery mechanism. The existing daemon lifecycle hooks are an option.

## Acceptance gates

1. Build Intel core with static Cronet and verify Mach-O min OS <= 13.0.
2. Run daemon regression tests, TUN and Naive configuration checks, service
   installation dry run, verify launcher architecture and minimum OS.
3. On an actual Ventura Mac, install the protected daemon and pair. Verify
   full YC profile application (including nested groups, DNS and SRS),
   system TUN, real traffic, Smart/Base/White/RU chains, Gemini, and direct
   LAN routing.
4. Exercise start/stop, sleep/wake, Wi-Fi/network changes, failed apply,
   daemon restart, hard crash, DNS/route restoration, uninstall. Confirm
   no traffic loop and no lasting DNS changes. Validate behavior with existing
   Karing turned off, then explicitly test coexistence only if needed.
5. Only after the real device passes: make a repeatable end-user install and
   add the native path to normal release CI. Do not publish a production-ready
   claim from a build-only result.

The separate earlier SFM.System compile experiment is diagnostic only and
must not be used as the installation path without suitable Apple signing.
