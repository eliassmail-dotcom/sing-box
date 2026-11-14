package group

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func TestLXGuardThreeHardFailures(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	if g.record("a", true, "site1") || g.record("a", true, "site2") {
		t.Fatal("one or two failures must not quarantine")
	}
	if !g.record("a", true, "site3") || !g.blocked("a") {
		t.Fatal("third failure must start quarantine")
	}
	if g.blocked("b") || g.record("a", true, "site4") {
		t.Fatal("quarantine must be per node and not restart on each failure")
	}
	now = now.Add(lxGuardQuarantine + time.Nanosecond)
	if g.blocked("a") {
		t.Fatal("quarantine should expire")
	}
}

func TestLXGuardNeedsIndependentEvidence(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	for _, site := range []string{"s1", "s2", "s3", "s4", "s5", "s6"} {
		if g.record("a", false, site) {
			t.Fatal("passive stream stalls alone must never quarantine")
		}
	}
	if !g.record("a", true, "site7") {
		t.Fatal("two separate stalls and one hard failure should confirm quarantine")
	}
}

func TestLXGuardWindowAndSuccess(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	g.record("a", true, "site1")
	g.record("a", true, "site2")
	now = now.Add(lxGuardWindow + time.Second)
	if g.record("a", true, "site3") {
		t.Fatal("old evidence must expire")
	}
	g.success("a")
	if g.record("a", true, "site4") || g.record("a", true, "site5") {
		t.Fatal("success must clear tentative hard failures")
	}
	if !g.record("a", true, "site6") {
		t.Fatal("a fresh set of failures must quarantine")
	}
	g.success("a")
	if !g.blocked("a") {
		t.Fatal("success must not shorten an active quarantine")
	}
}

func TestLXGuardDoesNotQuarantineOnOneBrokenSite(t *testing.T) {
	g := newLXPassiveGuard()
	for i := 0; i < 100; i++ {
		if g.record("node", true, "broken.example:443") {
			t.Fatal("repeated attempts to a single destination must not quarantine the proxy")
		}
	}
	if g.blocked("node") {
		t.Fatal("one broken website must not affect the entire node")
	}
}

func TestLXGuardSuspectGateRespectsContext(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	g.record("a", true, "site1")
	release, err := g.enter(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := g.enter(ctx, "a"); !errors.Is(err, context.Canceled) {
		t.Fatalf("queued dial should observe cancellation: %v", err)
	}
	release()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		release2, err := g.enter(context.Background(), "a")
		if err == nil {
			release2()
		}
	}()
	wg.Wait()
	now = now.Add(lxGuardWindow + time.Second)
	release3, err := g.enter(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	release3()
}

func TestLXPassiveReadClassification(t *testing.T) {
	if lxSuspiciousStreamRead(nil, 1, 16000) ||
		lxSuspiciousStreamRead(os.ErrDeadlineExceeded, 0, 16000) ||
		lxSuspiciousStreamRead(os.ErrDeadlineExceeded, 1, 200) ||
		lxSuspiciousStreamRead(os.ErrDeadlineExceeded, 1, 100000) ||
		lxSuspiciousStreamRead(context.Canceled, 1, 16000) {
		t.Fatal("unqualified stream read must not count as a stall")
	}
	if !lxSuspiciousStreamRead(os.ErrDeadlineExceeded, 40, 16000) {
		t.Fatal("qualified timeout should be a weak stall hint")
	}
}

func TestLXGuardSelectionSkipsQuarantine(t *testing.T) {
	a := newFailoverNode("base", 0)
	b := newFailoverNode("white", 0)
	g := newFailoverTestGroup(t, a, b)
	g.failover = false
	g.passiveGuard = newLXPassiveGuard()
	g.priorityOutbounds = map[string]bool{"base": true}
	g.history.StoreURLTestHistory("base", &adapter.URLTestHistory{Time: time.Now(), Delay: 10})
	g.history.StoreURLTestHistory("white", &adapter.URLTestHistory{Time: time.Now(), Delay: 200})
	g.setSelectedTCPLx(a)
	if got := g.pickForDialNode(N.NetworkTCP); got != a {
		t.Fatalf("preferred node should win while healthy: %v", got)
	}
	for _, site := range []string{"site1", "site2", "site3"} {
		g.passiveGuard.record("base", true, site)
	}
	if got := g.pickForDialNode(N.NetworkTCP); got != b {
		t.Fatalf("quarantined preferred node must yield to fallback: %v", got)
	}
	g.failover = true
	g.priorityOutbounds = nil
	if got, _ := g.failoverSelect(N.NetworkTCP, false); got != b {
		t.Fatalf("failover must release a quarantined hold: %v", got)
	}
}

func TestLXGuardColdStartSkipsQuarantinedNode(t *testing.T) {
	a := newFailoverNode("a", 0)
	b := newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	g.failover = false
	g.passiveGuard = newLXPassiveGuard()
	g.setSelectedTCPLx(a)
	for _, site := range []string{"site1", "site2", "site3"} {
		g.passiveGuard.record("a", true, site)
	}
	// No URLTest history for either node. The old cached selection must not win.
	if got := g.pickForDialNode(N.NetworkTCP); got != b {
		t.Fatalf("cold start must choose non-quarantined fallback: %v", got)
	}
}
