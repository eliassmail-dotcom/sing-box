package group

import (
    "context"
    "testing"
    "time"

    "github.com/sagernet/sing-box/adapter"
    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing/common/logger"
    N "github.com/sagernet/sing/common/network"
)

// LX base -> whitelist fallback: while the primary responds, even a faster
// backup is never selected. After failure, backup is used until the primary
// recovers; switching occurs in the core even when the iOS UI is suspended.
func TestPriorityFallback_BasePreferredFailAndRecover(t *testing.T) {
    base := newFailoverNode("base", 110*time.Millisecond)
    white := newFailoverNode("white", 10*time.Millisecond)
    g := newFailoverTestGroup(t, base, white)
    g.failover = false
    g.priorityOutbounds = map[string]bool{"base": true}
    if got, fresh := g.selectPriority(N.NetworkTCP); got == nil || got.Tag() != "base" || fresh {
        t.Fatalf("cold start must choose base, got %v fresh %v", got, fresh)
    }
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, base)
    assertSelected(t, g, N.NetworkUDP, base)

    base.setErr(context.DeadlineExceeded)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, white)
    assertSelected(t, g, N.NetworkUDP, white)

    base.setErr(nil)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, base)
    assertSelected(t, g, N.NetworkUDP, base)
}

func TestPriorityFallback_NoPrimaryAndNoBackupKeepsColdStart(t *testing.T) {
    base := newFailoverNode("base", 0)
    white := newFailoverNode("white", 0)
    g := newFailoverTestGroup(t, base, white)
    g.failover = false
    g.priorityOutbounds = map[string]bool{"base":true}
    base.setErr(context.DeadlineExceeded)
    white.setErr(context.DeadlineExceeded)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    selected, ok := g.selectPriority(N.NetworkTCP)
    if selected == nil || selected.Tag() != "base" || ok { t.Fatalf("expected cold-start base, selected=%v fresh=%v", selected, ok) }
}

func TestPriorityFallback_DialPickUsesPriorityAndNoInterruptFlag(t *testing.T) {
    base := newFailoverNode("base", 0)
    white := newFailoverNode("white", 0)
    g := newFailoverTestGroup(t, base, white)
    g.failover = false
    g.priorityOutbounds = map[string]bool{"base": true}
    g.history.StoreURLTestHistory("base", &adapter.URLTestHistory{Time:time.Now(), Delay:500})
    g.history.StoreURLTestHistory("white", &adapter.URLTestHistory{Time:time.Now(), Delay:10})
    if got := g.pickForDialNode(N.NetworkTCP); got == nil || got.Tag() != "base" { t.Fatalf("dial must prefer base, got %v", got) }
}

func TestPriorityFallback_ConfigValidation(t *testing.T) {
    for _, opts := range []option.URLTestOutboundOptions{
        {Outbounds:[]string{"base"}, PriorityOutbounds:[]string{"missing"}},
        {Outbounds:[]string{"base"}, PriorityOutbounds:[]string{"base","base"}},
        {Outbounds:[]string{"base"}, Mode:"round_robin", PriorityOutbounds:[]string{"base"}},
        {Outbounds:[]string{"base"}, Mode:"failover", PriorityOutbounds:[]string{"base"}},
    } {
        if _, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", opts); err == nil {
            t.Fatalf("invalid priority config accepted: %+v", opts)
        }
    }
    outbound, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", option.URLTestOutboundOptions{
        Outbounds:[]string{"base","white"}, PriorityOutbounds:[]string{"base"}, Mode:"least_test",
    })
    if err != nil {t.Fatal(err)}
    if !outbound.(*URLTest).priorityOutbounds["base"] {t.Fatal("missing primary")}
}
