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
patch("common/tls/client.go", [
    ("if options.Options.Fragment || options.Options.RecordFragment != nil {", "if options.Options.FinalMaskFragment != nil || options.Options.Fragment || options.Options.RecordFragment != nil {"),
    ("applyDetourFragmentDefault(&options)", """if options.Options.FinalMaskFragment != nil && options.Options.Engine != "" && options.Options.Engine != C.TLSEngineGo {
        return nil, E.New("finalmask_fragment requires Go TLS engine")
    }
    applyDetourFragmentDefault(&options)"""),
])
