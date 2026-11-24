#!/usr/bin/env bash
# lx:build-parity — reproducible Windows boxdd daemon build (peer review #7,
# F-04/F-06/F-08).
#
# This is the single source of truth for Windows parity builds: it applies the
# exact core preparation the b39 iOS workflow applies (prepare-b38.sh: upstream
# v1.14.4-lx.35 merge + FinalMask patch), then builds the boxdd daemon with the
# standard builder, and emits a build manifest recording the base commit, the
# upstream SHA and the output checksums. Any environment with git, bash and Go
# 1.26 can rebuild a comparable binary from the same commit.
#
# Usage (from the repository root, clean working tree):
#   bash .github/build-windows-parity.sh
#
# Optional environment:
#   LX_WIN_TAG=v1.14.4-lx.35-b39-windows  force the version tag reported by the
#                                         binary (git tag -f, mirroring what the
#                                         iOS workflow does with v1.14.4-lx.35-b39).
#   GOFLAGS/GOPROXY                        forwarded to the Go build as-is.
#
# Notes:
# - The script intentionally leaves the working tree in the prepared
#   (uncommitted merge + patches) state, same as the iOS CI job does in its
#   ephemeral checkout. Reset with `git reset --hard` after harvesting outputs.
# - The local Authenticode-gate patch (owner decision 2026-11-12) is NOT part
#   of this repository; apply it separately per machine if the daemon service
#   refuses to start an unsigned binary.
set -euxo pipefail

test -z "$(git status --porcelain)" || { echo "working tree not clean" >&2; exit 1; }

BASE_SHA=$(git rev-parse HEAD)
BASE_REF=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)

# prepare-b38.sh hardcodes python3; on Windows git-bash only `python` exists.
if ! command -v python3 >/dev/null 2>&1 && command -v python >/dev/null 2>&1; then
  PYSHIM=$(mktemp -d)
  printf '#!/usr/bin/env bash\nexec python "$@"\n' > "$PYSHIM/python3"
  chmod +x "$PYSHIM/python3"
  export PATH="$PYSHIM:$PATH"
fi

git submodule update --init

bash .github/prepare-b38.sh
UPSTREAM_SHA=$(git rev-parse lx35-upstream^{commit})
echo "Upstream LX35 commit: $UPSTREAM_SHA"

if [ -n "${LX_WIN_TAG:-}" ]; then
  git tag -f "$LX_WIN_TAG" HEAD
fi

mkdir -p dist
go run ./cmd/internal/build_boxdd -target windows/amd64 -output dist/sing-box-daemon.exe

# Peer review #8, F-08: record what the prepared tree actually is, and prove
# the binary was tested. LX_WIN_RACE=1 adds -race (needs a C toolchain, e.g.
# mingw-w64 on Windows).
PREPARED_TREE_SHA=$(git diff HEAD | sha256sum | cut -d' ' -f1)
PREPARE_SCRIPT_SHA=$(sha256sum .github/prepare-b38.sh | cut -d' ' -f1)
FINALMASK_PATCH_SHA=$(sha256sum .github/patch-b38-finalmask.py | cut -d' ' -f1)

RACE_FLAG=""
TEST_MODE="no -race"
if [ "${LX_WIN_RACE:-0}" = "1" ]; then
  RACE_FLAG="-race"
  TEST_MODE="-race"
fi
TEST_OUT=dist/sing-box-daemon-test-results.txt
go test $RACE_FLAG -count=1 -timeout=15m -ldflags "-checklinkname=0" \
  -tags "with_utls with_lx_command with_xhttp with_quic with_lx_chain" \
  ./common/dialer/ ./common/tls/ ./option/ ./protocol/vless/ ./protocol/group/ ./protocol/chain/ ./experimental/libbox/ 2>&1 | tee "$TEST_OUT"
TESTS_SUMMARY=$(grep -E '^(ok|FAIL)' "$TEST_OUT" | tr '\n\t' '  ')

SHA256=$(sha256sum dist/sing-box-daemon.exe | cut -d' ' -f1)
SIZE=$(stat -c %s dist/sing-box-daemon.exe)
VERSION=$(dist/sing-box-daemon.exe version | tr '\n' '; ')
GO_VERSION=$(go version | tr '\n' ' ')
BUILD_TAGS=$(cat release/DEFAULT_BUILD_TAGS_WINDOWS)

cat > dist/sing-box-daemon-manifest.json <<EOF
{
  "component": "sing-box-daemon (Windows boxdd)",
  "branch": "$BASE_REF",
  "base_commit": "$BASE_SHA",
  "upstream_lx35_commit": "$UPSTREAM_SHA",
  "preparation": ".github/prepare-b38.sh (upstream LX.35 merge -X ours + FinalMask patch .github/patch-b38-finalmask.py)",
  "prepare_script_sha256": "$PREPARE_SCRIPT_SHA",
  "finalmask_patch_sha256": "$FINALMASK_PATCH_SHA",
  "prepared_tree_diff_sha256": "$PREPARED_TREE_SHA",
  "tests": "PASS ($TEST_MODE); packages: common/dialer common/tls option protocol/vless protocol/group protocol/chain experimental/libbox; log: dist/sing-box-daemon-test-results.txt",
  "test_results": "$TESTS_SUMMARY",
  "version": "$VERSION",
  "go": "$GO_VERSION",
  "build_tags_default": "$BUILD_TAGS",
  "build_tags_extra": ["with_xhttp", "with_awg", "with_lx_command", "with_lx_chain", "with_trusttunnel", "with_external_windivert", "with_external_usbip_drivers"],
  "sha256": "$SHA256",
  "size_bytes": $SIZE,
  "authenticode": "unsigned; local gate exception applied per machine if needed (owner decision 2026-11-12)"
}
EOF

cat dist/sing-box-daemon-manifest.json
echo "Build complete: dist/sing-box-daemon.exe (sha256 $SHA256)"
