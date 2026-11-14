package group

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"
)

func TestLXGuardThreeHardFailures(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	if g.record("a", true) || g.record("a", true) {
		t.Fatal("one or two failures must not quarantine")
	}
	if !g.record("a", true) || !g.blocked("a") {
		t.Fatal("third failure must start quarantine")
	}
	if g.blocked("b") || g.record("a", true) {
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
	for i := 0; i < 6; i++ {
		if g.record("a", false) {
			t.Fatal("passive stream stalls alone must never quarantine")
		}
	}
	if !g.record("a", true) {
		t.Fatal("two separate stalls and one hard failure should confirm quarantine")
	}
}

func TestLXGuardWindowAndSuccess(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	g.record("a", true)
	g.record("a", true)
	now = now.Add(lxGuardWindow + time.Second)
	if g.record("a", true) {
		t.Fatal("old evidence must expire")
	}
	g.success("a")
	if g.record("a", true) || g.record("a", true) {
		t.Fatal("success must clear tentative hard failures")
	}
	if !g.record("a", true) {
		t.Fatal("a fresh set of failures must quarantine")
	}
	g.success("a")
	if !g.blocked("a") {
		t.Fatal("success must not shorten an active quarantine")
	}
}

func TestLXGuardSuspectGateRespectsContext(t *testing.T) {
	now := time.Unix(100, 0)
	g := newLXPassiveGuard()
	g.now = func() time.Time { return now }
	g.record("a", true)
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
		if err == nil { release2() }
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
