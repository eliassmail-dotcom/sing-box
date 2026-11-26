package group

import (
	"context"
	"sync"
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
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, base)
	assertSelected(t, g, N.NetworkUDP, base)

	base.setErr(context.DeadlineExceeded)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, white)
	assertSelected(t, g, N.NetworkUDP, white)

	base.setErr(nil)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
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

	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, baseA)

	baseA.setErr(context.DeadlineExceeded)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, baseB)

	baseB.setErr(context.DeadlineExceeded)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, white)

	baseA.setErr(nil)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, baseA)
}

func TestPriorityFallback_NoPrimaryAndNoBackupKeepsColdStart(t *testing.T) {
	base := newFailoverNode("base", 0)
	white := newFailoverNode("white", 0)
	g := newFailoverTestGroup(t, base, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	base.setErr(context.DeadlineExceeded)
	white.setErr(context.DeadlineExceeded)
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	selected, ok := g.selectPriority(N.NetworkTCP)
	if selected == nil || selected.Tag() != "base" || ok {
		t.Fatalf("expected cold-start base, selected=%v fresh=%v", selected, ok)
	}
}

func TestPriorityFallback_DialPickUsesPriorityAndNoInterruptFlag(t *testing.T) {
	base := newFailoverNode("base", 0)
	white := newFailoverNode("white", 0)
	g := newFailoverTestGroup(t, base, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	g.history.StoreURLTestHistory("base", &adapter.URLTestHistory{Time: time.Now(), Delay: 500})
	g.history.StoreURLTestHistory("white", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	if got := g.pickForDialNode(N.NetworkTCP); got == nil || got.Tag() != "base" {
		t.Fatalf("dial must prefer base, got %v", got)
	}
}

// Penalties are considered inside the preferred tier, but never promote White
// while any Base candidate still has a successful probe.
func TestPriorityFallback_PenaltyRankingWithinBaseTier(t *testing.T) {
	baseFast := newFailoverNode("base-fast", 0)
	baseStable := newFailoverNode("base-stable", 0)
	white := newFailoverNode("white", 0)
	g := newFailoverTestGroup(t, baseFast, baseStable, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base-fast": true, "base-stable": true}
	for _, item := range []struct {
		tag   string
		delay uint16
	}{
		{"base-fast", 10}, {"base-stable", 200}, {"white", 1},
	} {
		g.history.StoreURLTestHistory(item.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: item.delay})
	}
	for i := 0; i < 5; i++ {
		g.penaltyAdd("base-fast")
	}
	if got := g.pickForDialNode(N.NetworkTCP); got == nil || got.Tag() != "base-stable" {
		t.Fatalf("Smart must select the healthier Base node, not the penalized fastest node or White; got %v", got)
	}
}

// The selection fields have one lock domain even when a dial fallback races
// with the normal dashboard/health readers.
func TestPriorityFallback_SelectedOutboundReadWriteRace(t *testing.T) {
	a := newFailoverNode("a", 0)
	b := newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 10000; i++ {
			g.moveSelection(N.NetworkTCP, a)
			g.moveSelection(N.NetworkTCP, b)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20000; i++ {
			g.selectedLx()
			g.failoverHeld()
		}
	}()
	wg.Wait()
}

func TestPriorityFallback_ConfigValidation(t *testing.T) {
	for _, opts := range []option.URLTestOutboundOptions{
		{Outbounds: []string{"base"}, PriorityOutbounds: []string{"missing"}},
		{Outbounds: []string{"base"}, PriorityOutbounds: []string{"base", "base"}},
		{Outbounds: []string{"base"}, Mode: "round_robin", PriorityOutbounds: []string{"base"}},
		{Outbounds: []string{"base"}, Mode: "failover", PriorityOutbounds: []string{"base"}},
	} {
		if _, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", opts); err == nil {
			t.Fatalf("invalid priority config accepted: %+v", opts)
		}
	}
	outbound, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", option.URLTestOutboundOptions{
		Outbounds: []string{"base", "white"}, PriorityOutbounds: []string{"base"}, Mode: "least_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outbound.(*URLTest).priorityOutbounds["base"] {
		t.Fatal("missing primary")
	}
}

func TestPriorityFallback_ThreeTierFailureRecoveryAndRotation(t *testing.T) {
	base := newFailoverNode("base", 120*time.Millisecond)
	chainA := newFailoverNode("chain-a", 80*time.Millisecond)
	chainB := newFailoverNode("chain-b", 90*time.Millisecond)
	white := newFailoverNode("white", 5*time.Millisecond)
	g := newFailoverTestGroup(t, base, chainA, chainB, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	g.secondaryPriorityOutbounds = map[string]bool{"chain-a": true, "chain-b": true}
	check := func(want *failoverNode) {
		t.Helper()
		if _, err := g.URLTest(context.Background()); err != nil {
			t.Fatal(err)
		}
		assertSelected(t, g, N.NetworkTCP, want)
		assertSelected(t, g, N.NetworkUDP, want)
		if got := g.pickForDialNode(N.NetworkTCP); got == nil || got.Tag() != want.Tag() {
			t.Fatalf("dial selected %v, want %s", got, want.Tag())
		}
	}
	check(base)
	base.setErr(context.DeadlineExceeded)
	check(chainA)
	if tag, err := g.cycleNode(0); err != nil || tag != "chain-b" {
		t.Fatalf("rotation must stay in chain tier: %q %v", tag, err)
	}
	chainA.setErr(context.DeadlineExceeded)
	chainB.setErr(context.DeadlineExceeded)
	check(white)
	chainA.setErr(nil)
	check(chainA)
	base.setErr(nil)
	check(base)
}

func TestPriorityFallback_SecondaryValidation(t *testing.T) {
	for _, opts := range []option.URLTestOutboundOptions{
		{Outbounds: []string{"a", "c", "w"}, SecondaryPriorityOutbounds: []string{"c"}},
		{Outbounds: []string{"a", "c", "w"}, PriorityOutbounds: []string{"a"}, SecondaryPriorityOutbounds: []string{"a"}},
		{Outbounds: []string{"a", "c", "w"}, PriorityOutbounds: []string{"a"}, SecondaryPriorityOutbounds: []string{"missing"}},
		{Outbounds: []string{"a", "c", "w"}, PriorityOutbounds: []string{"a"}, SecondaryPriorityOutbounds: []string{"c", "c"}},
		{Outbounds: []string{"a", "c", "w"}, PriorityOutbounds: []string{"a"}, SecondaryPriorityOutbounds: []string{"c"}, Mode: "failover"},
	} {
		if _, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", opts); err == nil {
			t.Fatalf("invalid secondary config accepted: %+v", opts)
		}
	}
	outbound, err := NewURLTest(context.Background(), nil, logger.NOP(), "root", option.URLTestOutboundOptions{
		Outbounds: []string{"a", "c", "w"}, PriorityOutbounds: []string{"a"}, SecondaryPriorityOutbounds: []string{"c"}, Mode: "least_test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !outbound.(*URLTest).secondaryPriorityOutbounds["c"] {
		t.Fatal("missing secondary tier")
	}
}
