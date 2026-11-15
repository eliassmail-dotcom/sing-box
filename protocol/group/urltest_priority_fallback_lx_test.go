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

// Smart's flat pool can contain many Base leaves. One healthy Base node
// must keep White out of the route even when White is substantially faster.
func TestPriorityFallback_AnyHealthyBaseBeatsFasterWhite(t *testing.T) {
    baseA := newFailoverNode("base-a", 80*time.Millisecond)
    baseB := newFailoverNode("base-b", 120*time.Millisecond)
    white := newFailoverNode("white", 10*time.Millisecond)
    g := newFailoverTestGroup(t, baseA, baseB, white)
    g.failover = false
    g.priorityOutbounds = map[string]bool{"base-a": true, "base-b": true}

    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, baseA)

    baseA.setErr(context.DeadlineExceeded)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, baseB)

    baseB.setErr(context.DeadlineExceeded)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, white)

    baseA.setErr(nil)
    if _, err := g.URLTest(context.Background()); err != nil { t.Fatal(err) }
    assertSelected(t, g, N.NetworkTCP, baseA)
}

// A successful URLTest history alone does not make a Base path usable after
// LX has rejected its real connections. Another eligible Base still wins, but
// when all Base paths are rejected Smart must move to White and later recover.
func TestPriorityFallback_RejectedBasesUseWhiteAndRecover(t *testing.T) {
	baseA := newFailoverNode("base-a", 80*time.Millisecond)
	baseB := newFailoverNode("base-b", 120*time.Millisecond)
	white := newFailoverNode("white", 10*time.Millisecond)
	g := newFailoverTestGroup(t, baseA, baseB, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base-a": true, "base-b": true}

	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, baseA)

	// One bad Base cannot promote White while another Base is eligible.
	for i := int64(0); i < penaltyThreshold; i++ {
		g.penaltyAdd("base-a")
	}
	if got, _ := g.selectPriority(N.NetworkTCP); got != baseB {
		t.Fatalf("healthy Base must beat White, got %v", got)
	}
	if got := g.penaltyBest(N.NetworkTCP, "base-a"); got != baseB {
		t.Fatalf("dial fallback must prefer healthy Base, got %v", got)
	}

	// Both Bases are rejected although URLTest history still says 'alive'.
	for i := int64(0); i < penaltyThreshold; i++ {
		g.penaltyAdd("base-b")
	}
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		if got, _ := g.selectPriority(network); got != white {
			t.Fatalf("%s must fall back to White, got %v", network, got)
		}
		if got := g.pickForDialNode(network); got != white {
			t.Fatalf("%s dial must avoid rejected Base, got %v", network, got)
		}
	}
	if got := g.penaltyBest(N.NetworkTCP, "base-a"); got != white {
		t.Fatalf("failed-dial fallback must skip rejected Base, got %v", got)
	}
	g.performSelectionUpdate(false)
	assertSelected(t, g, N.NetworkTCP, white)
	assertSelected(t, g, N.NetworkUDP, white)

	// A real proof of life resets rejection and restores the Base tier.
	g.penaltyReset("base-b")
	if got, _ := g.selectPriority(N.NetworkTCP); got != baseB {
		t.Fatalf("recovered Base must take back priority, got %v", got)
	}
	g.performSelectionUpdate(false)
	assertSelected(t, g, N.NetworkTCP, baseB)
	assertSelected(t, g, N.NetworkUDP, baseB)
}

// Weak but sub-threshold failure signals are not a blanket ban. Smart stays on
// Base unless LX's existing path-rejection threshold has actually been reached.
func TestPriorityFallback_SubThresholdPenaltyKeepsBase(t *testing.T) {
	base := newFailoverNode("base", 80*time.Millisecond)
	white := newFailoverNode("white", 10*time.Millisecond)
	g := newFailoverTestGroup(t, base, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	for i := int64(1); i < penaltyThreshold; i++ {
		g.penaltyAdd("base")
	}
	if got, _ := g.selectPriority(N.NetworkTCP); got != base {
		t.Fatalf("Base below rejection threshold must retain priority, got %v", got)
	}
}

// A quarantine is stronger than a ping result: even with fresh successful
// URLTest history, both quarantined Base nodes yield to White until expiry.
func TestPriorityFallback_AllBaseQuarantinedThenRecover(t *testing.T) {
	baseA := newFailoverNode("base-a", 80*time.Millisecond)
	baseB := newFailoverNode("base-b", 120*time.Millisecond)
	white := newFailoverNode("white", 10*time.Millisecond)
	g := newFailoverTestGroup(t, baseA, baseB, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base-a": true, "base-b": true}
	g.passiveGuard = newLXPassiveGuard()
	now := time.Unix(100, 0)
	g.passiveGuard.now = func() time.Time { return now }
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}

	for _, tag := range []string{"base-a", "base-b"} {
		for _, site := range []string{"site1", "site2", "site3"} {
			g.passiveGuard.record(tag, true, site)
		}
		if !g.passiveGuard.blocked(tag) {
			t.Fatalf("%s should be quarantined", tag)
		}
	}
	if got, _ := g.selectPriority(N.NetworkTCP); got != white {
		t.Fatalf("all quarantined Base paths must use White, got %v", got)
	}
	g.performSelectionUpdate(false)
	assertSelected(t, g, N.NetworkTCP, white)
	now = now.Add(lxGuardQuarantine + time.Nanosecond)
	if got, _ := g.selectPriority(N.NetworkTCP); got != baseA {
		t.Fatalf("Base should regain priority after quarantine expiry, got %v", got)
	}
	g.performSelectionUpdate(false)
	assertSelected(t, g, N.NetworkTCP, baseA)
}

// A previously selected route must not escape eligibility validation at cold
// start, nor should the cycle command offer a rejected/quarantined node.
func TestPriorityFallback_ColdStartAndNextNodeRespectRejection(t *testing.T) {
	base := newFailoverNode("base", 80*time.Millisecond)
	whiteA := newFailoverNode("white-a", 10*time.Millisecond)
	whiteB := newFailoverNode("white-b", 50*time.Millisecond)
	g := newFailoverTestGroup(t, base, whiteA, whiteB)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	for i := int64(0); i < penaltyThreshold; i++ {
		g.penaltyAdd("base")
	}

	// Neither tier has URLTest history: cold start may use an eligible White,
	// but must never attempt the rejected Base.
	if got, fresh := g.selectPriority(N.NetworkTCP); got != whiteA || fresh {
		t.Fatalf("cold-start White expected when Base rejected; got %v, fresh=%v", got, fresh)
	}
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	// URLTest proof-of-life resets penalties; recreate a rejected Base.
	for i := int64(0); i < penaltyThreshold; i++ {
		g.penaltyAdd("base")
	}
	got, err := g.cycleNode(0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "white-b" && got != "white-a" {
		t.Fatalf("next-node must remain in eligible White tier, got %q", got)
	}

	// If all alternatives become rejected, do not route through an unusable
	// node solely to preserve the historical cold-start behavior.
	for _, tag := range []string{"white-a", "white-b"} {
		for i := int64(0); i < penaltyThreshold; i++ {
			g.penaltyAdd(tag)
		}
	}
	if got, _ := g.selectPriority(N.NetworkTCP); got != nil {
		t.Fatalf("no eligible path must return nil, got %v", got)
	}
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
