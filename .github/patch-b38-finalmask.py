#!/usr/bin/env python3
from pathlib import Path
def patch(path, edits):
    p = Path(path)
    s = p.read_text()
    for old, new in edits:
        assert s.count(old) == 1, (path, old, s.count(old))
        s = s.replace(old, new, 1)
    p.write_text(s)
p = Path("option/tls.go")
s = p.read_text()
old = next(l for l in s.splitlines() if 'RecordFragment ' in l and 'json:' in l)
patch("option/tls.go", [(old, old + '\n\tFinalMaskFragment *LXFinalMaskFragmentOptions \x60json:"finalmask_fragment,omitempty"\x60')])
for path, cls, constructor in [
    ("common/tls/utls_client.go", "UTLSClientConfig", "newUTLSClient"),
    ("common/tls/std_client.go", "STDClientConfig", "newSTDClient"),
]:
    s = Path(path).read_text()
    old = next(l for l in s.splitlines() if l.strip().startswith("fragmentChosen") and "bool" in l)
    fn = next(l for l in s.splitlines() if l.startswith("func "+constructor+"("))
    oldwrap = next(l for l in s.splitlines() if "if (c.fragment || c.recordFragment)" in l)
    oldclone = next(l for l in s.splitlines() if "fragmentChosen:" in l and "c.fragmentChosen" in l)
    oldinit = next(l for l in s.splitlines() if "fragmentChosen:" in l and "options.Fragment" in l)
    patch(path, [
      (old, old + "\n\tfinalMask *option.LXFinalMaskFragmentOptions"),
      (fn, fn + "\n\tif err := options.FinalMaskFragment.Validate(); err != nil { return nil, err }"),
      (oldwrap, "\tif c.finalMask != nil && !sniffGuardShapedLx(conn) {\n\t\tconn = newLXFinalMaskConn(conn, c.finalMask)\n\t} else "+oldwrap.strip()),
      (oldclone, oldclone + "\n\t\tfinalMask: c.finalMask,"),
      (oldinit, oldinit.replace("options.Fragment ||", "options.FinalMaskFragment != nil || options.Fragment ||") + "\n\t\tfinalMask: options.FinalMaskFragment,"),
    ])
# F3 is fail-closed on the unprepared b39 bool representation. Only this
# LX35+FinalMask preparation can distinguish an omitted record_fragment from
# an explicit false, and detect FinalMask and per-handshake sniff_guard.
patch("common/tls/adaptive_fragment_lx.go", [
    ('"github.com/sagernet/sing-box/adapter"', '"github.com/sagernet/sing-box/adapter"\n\t"github.com/sagernet/sing-box/common/lxsniffguard"'),
    ('const adaptiveFragmentPreparedLx = false', 'const adaptiveFragmentPreparedLx = true'),
    ('return false // prepared eligibility', 'return !options.Fragment && options.RecordFragment == nil && options.FinalMaskFragment == nil && options.FragmentFallbackDelay == 0 && options.Spoof == "" && options.SpoofMethod == ""'),
    ('return false // prepared context eligibility', 'return lxsniffguard.AttemptFromContext(ctx) == nil'),
])
patch("common/tls/client.go", [
    ("if options.Options.Fragment || options.Options.RecordFragment != nil {", "if options.Options.FinalMaskFragment != nil || options.Options.Fragment || options.Options.RecordFragment != nil {"),
    ("applyDetourFragmentDefault(&options)", """if options.Options.FinalMaskFragment != nil && options.Options.Engine != "" && options.Options.Engine != C.TLSEngineGo {
        return nil, E.New("finalmask_fragment requires Go TLS engine")
    }
    applyDetourFragmentDefault(&options)"""),
])
