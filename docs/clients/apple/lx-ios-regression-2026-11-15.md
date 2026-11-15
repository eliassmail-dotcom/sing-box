# LX iOS regression build — 2026-11-15

Apple client: [feature/lx-adaptive-health-ui @ 90108f9f2abc3cbd333e417f8a035f01e357084f](https://github.com/eliassmail-dotcom/sing-box-for-apple/commit/90108f9f2abc3cbd333e417f8a035f01e357084f).

Acceptance criteria for the unsigned GBox IPA:

- Restore the original `ExtensionProfile.start()` and `install()` from
  the pre-first-start-workaround Apple client; remove temporary startup
  diagnostics without changing native LX routing.
- The Strategy card retains its strategy tiles and live
  `Основной маршрут` / `Gemini` rows.
- The Resilience presets appear in an independently reorderable/hideable
  Dashboard card, immediately after Strategy by default. Tile typography,
  neutral background, active outline, and corner radius match Strategy.
- Existing Gemini Chains, Control Center Next Node, LX Reliability, local
  config generator, and all prior XCTest checks remain enabled.
- Publish `SFI-lx-local-generator-unsigned-ipa` only after the entire
  workflow has passed. iPhone runtime VPN/Network Extension registration
  still requires separate real-device verification, especially after GBox
  re-signing.
