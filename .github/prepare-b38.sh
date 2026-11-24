#!/usr/bin/env bash
set -euxo pipefail
git fetch --no-tags --force https://github.com/Leadaxe/sing-box-lx.git \
  refs/tags/v1.14.4-lx.35:refs/tags/lx35-upstream
UPSTREAM_SHA=$(git rev-parse lx35-upstream^{commit})
git merge-base HEAD "$UPSTREAM_SHA" >/dev/null
echo "Upstream LX35 commit: $UPSTREAM_SHA"
# Prefer our custom extensions where source edits overlap; accept all
# non-conflicting upstream fixes. Do not overwrite the released b36.
git -c user.name="LX IPA Builder" -c user.email="github-actions@users.noreply.github.com" \
  merge --no-commit --no-ff -X ours lx35-upstream
test -z "$(git ls-files -u)"
# Preserve b36's validated URLTest/failover subsystem; mixing it
# with new upstream group internals caused a selection-lock deadlock.
git restore --source=HEAD --staged --worktree -- protocol/group/
# LX35 removed the b36 ClientOptions.DialedThroughDetour path.
# Restore our b36 authenticated-IP-race TLS implementation, retaining
# LX35's new sniffGuardConnLx in its three handshake call sites.
git show HEAD:common/tls/client.go > common/tls/client.go
python3 - <<'PY'
from pathlib import Path
p = Path("common/tls/client.go")
t = p.read_text()
sites = [
  ('ctx, stage := beginHandshakeLx(ctx, config) // lx: SPEC 139',
   'ctx, stage := beginHandshakeLx(ctx, config) // lx: SPEC 139\\n\\tconn = sniffGuardConnLx(ctx, conn, config) // LX35'),
  ('handshakeCtx, stage := beginHandshakeLx(attemptCtx, config)',
   'handshakeCtx, stage := beginHandshakeLx(attemptCtx, config)\\n\\t\\t\\t\\traw = sniffGuardConnLx(handshakeCtx, raw, config) // LX35'),
  ('handshakeCtx, stage := beginHandshakeLx(ctx, d.config)',
   'handshakeCtx, stage := beginHandshakeLx(ctx, d.config)\\n\\tconn = sniffGuardConnLx(handshakeCtx, conn, d.config) // LX35'),
]
for old, new in sites:
    assert t.count(old) == 1, (old, t.count(old))
    t = t.replace(old, new.replace('\\n', '\n').replace('\\t', '\t'), 1)
# LX35 exposes RecordFragment as *bool (nil means unspecified).
# Keep b36 default-on-detour semantics, but honor explicit false.
assert t.count('if options.Options.Fragment || options.Options.RecordFragment {') == 1
t = t.replace('if options.Options.Fragment || options.Options.RecordFragment {',
              'if options.Options.Fragment || options.Options.RecordFragment != nil {')
assert t.count('options.Options.RecordFragment = true') == 1
t = t.replace('options.Options.RecordFragment = true',
              'recordFragment := true\\n\\toptions.Options.RecordFragment = &recordFragment'.replace('\\n', chr(10)).replace('\\t', chr(9)))
assert "DialedThroughDetour bool" in t
assert t.count("sniffGuardConnLx(") == 3
p.write_text(t)
PY
echo "Merged upstream files:"
git diff HEAD --stat | tail -45
# Guard core features added after the upstream base.
grep -q 'DialVerifiedTCP' common/tls/client.go
grep -q 'TCPConcurrent' option/outbound.go
grep -q 'ResetTCPConcurrentHistory' protocol/vless/outbound.go
grep -q 'passive_guard' option/group.go
grep -q 'with_lx_chain' .github/workflows/build-ipa-lx.yml || true
echo "$UPSTREAM_SHA" > /tmp/lx35-upstream-sha

python3 .github/patch-b38-finalmask.py
gofmt -w option/tls.go option/lx_finalmask_fragment.go common/tls/{client,utls_client,std_client,lx_finalmask_conn,lx_finalmask_conn_test,lx_finalmask_reality_test}.go
