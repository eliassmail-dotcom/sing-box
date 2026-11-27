#!/usr/bin/env bash
set -euo pipefail
# Run only after compiling the exact merged tree. Native parser/box.New, no mock.
: "${APPLE_TAGS:?derive production tags before running}"
: "${RUNNER_TEMP:?}"
apple_sha=eae7921330d0e154b20a29db7c6051b9eab2a6bf
apple="$RUNNER_TEMP/b50-apple-source"
dir="$RUNNER_TEMP/b50-config-check"
mkdir -p "$dir"
git clone --no-checkout --filter=blob:none https://github.com/eliassmail-dotcom/sing-box-for-apple.git "$apple"
git -C "$apple" checkout --detach "$apple_sha"
test "$(git -C "$apple" rev-parse HEAD)" = "$apple_sha"
swiftc "$apple/Library/Network/LXGeminiBuilder.swift" \
  "$apple/Library/Network/LXProfileOverrides.swift" \
  migration/b50/ExportProfiles.swift -o "$dir/export-profiles"
"$dir/export-profiles" "$dir/profiles"
# Linux uses the supported LLVM linker; Darwin uses its normal linker.
ldflags='-checklinkname=0'
if [ "$(uname -s)" = Linux ]; then ldflags="$ldflags -extldflags=-fuse-ld=lld"; fi
go build -ldflags "$ldflags" -tags "$APPLE_TAGS" -o "$dir/sing-box" ./cmd/sing-box
for profile in "$dir"/profiles/generated-*.json; do
  "$dir/sing-box" check -c "$profile"
  echo "PASS native check $(basename "$profile")"
done
for profile in "$dir"/profiles/invalid-*.json; do
  if "$dir/sing-box" check -c "$profile" >"$dir/invalid.log" 2>&1; then
    echo "::error::Unexpected acceptance of $(basename "$profile")"
    exit 1
  fi
  cat "$dir/invalid.log"
  case "$(basename "$profile")" in
    invalid-idle-timeout.json) grep -F 'no longer creates link instances' "$dir/invalid.log" ;;
    invalid-strip.json) grep -F 'lx.detour.strip' "$dir/invalid.log" ;;
    *) exit 1 ;;
  esac
done
echo "Four generated profiles passed native parser/Box.New; both removed legacy fields rejected with actionable errors." >> "$GITHUB_STEP_SUMMARY"
