#!/usr/bin/env bash
# lx:build-parity — reproducible Windows boxdd daemon build (peer review #9).
#
# Builds from an already-prepared iOS core: the core integration (upstream
# merge, FinalMask, F1-F3) lives in the branch history and was validated by
# the iOS workflow before merge. No on-the-fly preparation is applied; the old
# b39 flow (prepare-b38.sh + EXPECTED_UPSTREAM_SHA) is kept in the repository
# for historical reproduction of b39-era builds only.
#
# Required environment:
#   LX_PREPARED_SHA — SHA of the verified prepared iOS core commit; must be an
#                      ancestor of HEAD (the provenance of the core).
#   LX_UPSTREAM_SHA — upstream tag commit the core integrated (LX.35→LX.36).
# Optional:
#   LX_WIN_TAG=v1.14.4-lx.36-b41-windows   force the version tag (git tag -f).
#   LX_WORKFLOW_RUN=45688648290             GitHub Actions run that validated the core.
#   LX_WIN_RACE=1                           run the test set with -race.
#
# The script intentionally leaves the working tree clean (no state is mutated
# beyond an optional local tag).
set -euxo pipefail

: "${LX_PREPARED_SHA:?set LX_PREPARED_SHA to the prepared iOS core commit}"
: "${LX_UPSTREAM_SHA:?set LX_UPSTREAM_SHA to the integrated upstream commit}"

# Ignore submodule pointer drift here: right after merging a prepared core the
# recorded gitlinks may be ahead of the checked-out working copies; the update
# below syncs them deterministically to the recorded pins.
test -z "$(git status --porcelain --ignore-submodules=all)" || { echo "working tree not clean" >&2; exit 1; }
git merge-base --is-ancestor "$LX_PREPARED_SHA" HEAD || { echo "LX_PREPARED_SHA is not an ancestor of HEAD" >&2; exit 1; }

BASE_SHA=$(git rev-parse HEAD)
BASE_TREE=$(git rev-parse HEAD^{tree})

if [ -n "${LX_WIN_TAG:-}" ]; then
  git tag -f "$LX_WIN_TAG" HEAD
fi

# Sync submodule working copies to the recorded gitlinks (expected pointer
# drift right after merging a prepared core); --init also fetches new pins.
git submodule update --init

mkdir -p dist
go run ./cmd/internal/build_boxdd -target windows/amd64 -output dist/sing-box-daemon.exe

# Test the built tree (the same packages as the iOS b41 regression set).
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
SUBMODULES=$(git submodule status | tr '\n' '; ')
WINDOWS_COMMITS=$(git log --oneline "$LX_PREPARED_SHA"..HEAD | tr '\n' '; ')

cat > dist/sing-box-daemon-manifest.json <<EOF
{
  "component": "sing-box-daemon (Windows boxdd)",
  "branch": "windows/build-parity",
  "head_commit": "$BASE_SHA",
  "head_tree": "$BASE_TREE",
  "prepared_ios_core": "$LX_PREPARED_SHA",
  "ios_workflow_run": "${LX_WORKFLOW_RUN:-n/a}",
  "upstream_lx36_commit": "$LX_UPSTREAM_SHA",
  "windows_commits": "$WINDOWS_COMMITS",
  "submodules": "$SUBMODULES",
  "version": "$VERSION",
  "go": "$GO_VERSION",
  "build_tags_default": "$BUILD_TAGS",
  "build_tags_extra": ["with_xhttp", "with_awg", "with_lx_command", "with_lx_chain", "with_trusttunnel", "with_external_windivert", "with_external_usbip_drivers"],
  "tests": "PASS ($TEST_MODE); packages: common/dialer common/tls option protocol/vless protocol/group protocol/chain experimental/libbox; log: dist/sing-box-daemon-test-results.txt",
  "test_results": "$TESTS_SUMMARY",
  "sha256": "$SHA256",
  "size_bytes": $SIZE,
  "authenticode": "unsigned; local gate exception applied per machine if needed (owner decision 2026-11-12)"
}
EOF

cat dist/sing-box-daemon-manifest.json
echo "Build complete: dist/sing-box-daemon.exe (sha256 $SHA256)"
