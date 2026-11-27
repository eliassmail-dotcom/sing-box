package group

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func rrMultiLinks(f *healFixture) []string {
	return []string{f.g.link + "/first", f.g.link + "/second", f.g.link + "/third"}
}

func TestB50RRMultiEndpointIdentity(t *testing.T) {
	if rrEndpointKey([]string{"ab", "c"}) == rrEndpointKey([]string{"a", "bc"}) ||
		rrEndpointKey([]string{"a", "b"}) == rrEndpointKey([]string{"b", "a"}) ||
		rrEndpointKey([]string{"a"}) == rrEndpointKey([]string{"a", "b"}) {
		t.Fatal("distinct ordered endpoint sets share a flight key")
	}
	if rrEndpointKey([]string{"a", "b"}) != rrEndpointKey([]string{"a", "b"}) {
		t.Fatal("identical endpoint lists must share a flight key")
	}
}

func TestB50RRMultiAnySuccessAndAllFail(t *testing.T) {
	f := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	f.g.links = rrMultiLinks(f)
	q := f.g.rrQueue()
	f.nodes["n"].probeFails.Store(1)
	got := f.g.rrSelfProbe(context.Background(), f.nodes["n"], time.Time{}, false)
	if !got.answered || got.err != nil || got.leaf != "n" {
		t.Fatalf("one failure must not kill the node: %+v", got)
	}
	waitLong(t, func() bool { return q.inFlight() == 0 }, 3*time.Second)
	f.nodes["n"].dead.Store(true)
	before := f.nodes["n"].probes.Load()
	got = f.g.rrSelfProbe(context.Background(), f.nodes["n"], time.Time{}, false)
	if got.answered || got.err == nil || got.cancelled() || f.nodes["n"].probes.Load()-before != 3 {
		t.Fatalf("all endpoints must fail for a no-answer verdict: %+v", got)
	}
	waitLong(t, func() bool { return q.inFlight() == 0 }, 3*time.Second)
}

func TestB50RRMultiRoundPhysicalCapAndFreeze(t *testing.T) {
	tags := make([]string, 18)
	for i := range tags {
		tags[i] = fmt.Sprintf("n%d", i)
	}
	f := newHealFixture(t, tags, tags, 0)
	f.g.links = rrMultiLinks(f)
	hold := make(chan struct{})
	for _, n := range f.nodes {
		n.hold = hold
	}
	defer close(hold)
	q := f.g.rrQueue()
	active := func() int32 {
		var count int32
		for _, n := range f.nodes {
			count += n.active.Load()
		}
		return count
	}
	if !f.s.rrStartRound(f.s.rrHealCheck) {
		t.Fatal("no round")
	}
	waitLong(t, func() bool { return active() == 15 }, 3*time.Second)
	for range 20 {
		if active() > rrQueueCap || q.inFlight() > rrQueueCap {
			t.Fatalf("physical cap violated: active=%d reserved=%d", active(), q.inFlight())
		}
		time.Sleep(5*time.Millisecond)
	}
	f.s.balancer.heal.freeze()
	waitLong(t, func() bool { return !f.s.balancer.heal.roundBusy() && q.inFlight() == 0 }, 3*time.Second)
	var probes int32
	for _, n := range f.nodes {
		probes += n.probes.Load()
	}
	if probes != 15 {
		t.Fatalf("a queued endpoint started after freeze: %d probes", probes)
	}
}

func TestB50RRMultiIdenticalFlightsOnly(t *testing.T) {
	a := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	b := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	c := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	a.g.links = rrMultiLinks(a)
	b.g.history, b.g.outbound, b.g.links = a.g.history, a.g.outbound, append([]string(nil), a.g.links...)
	c.g.history, c.g.outbound, c.g.links = a.g.history, a.g.outbound, []string{a.g.links[1], a.g.links[0], a.g.links[2]}
	n := a.nodes["n"]
	hold := make(chan struct{})
	n.hold = hold
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan rrProbe, 3)
	q := a.g.rrQueue()
	go func() { done <- a.g.rrSelfProbe(ctx, n, time.Time{}, false) }()
	waitLong(t, func() bool { return n.active.Load() == 3 }, 3*time.Second)
	go func() { done <- b.g.rrSelfProbe(ctx, n, time.Time{}, false) }()
	waitLong(t, func() bool {
		q.access.Lock()
		defer q.access.Unlock()
		flight := q.flights[rrFlightKey{leaf: "n", link: rrEndpointKey(a.g.links)}]
		return flight != nil && flight.waiters == 2
	}, 3*time.Second)
	go func() { done <- c.g.rrSelfProbe(ctx, n, time.Time{}, false) }()
	waitLong(t, func() bool { return n.active.Load() == 6 }, 3*time.Second)
	if q.inFlight() != 6 {
		t.Fatalf("dedup must return unused reservations, got %d", q.inFlight())
	}
	close(hold)
	for range 3 {
		select {
		case got := <-done:
			if !got.answered {
				t.Fatalf("flight failed: %+v", got)
			}
		case <-time.After(3*time.Second):
			t.Fatal("flight did not complete")
		}
	}
	waitLong(t, func() bool { return q.inFlight() == 0 }, 3*time.Second)
}

func TestB50RRMultiWaitCancellationAndLifeFreeze(t *testing.T) {
	f := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	f.g.links = rrMultiLinks(f)
	q := f.g.rrQueue()
	owner := new(rrQueueOwner)
	if !q.acquire(context.Background(), owner, rrQueueCap) {
		t.Fatal("failed to reserve queue")
	}
	defer q.release(rrQueueCap)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan rrProbe, 1)
	go func() { done <- f.g.rrSelfProbe(ctx, f.nodes["n"], time.Time{}, false) }()
	waiting := func() bool {
		q.access.Lock()
		defer q.access.Unlock()
		return len(f.s.balancer.heal.queue.waiting) > 0
	}
	waitLong(t, waiting, 3*time.Second)
	cancel()
	select {
	case got := <-done:
		if !got.cancelled() || got.answered {
			t.Fatalf("queue withdrawal is not a no-answer verdict: %+v", got)
		}
	case <-time.After(3*time.Second):
		t.Fatal("withdrawal did not finish")
	}
	track := f.s.balancer.trackOf("n")
	if !f.s.rrLifeProbe(f.nodes["n"], track, rrClock(time.Now()), false) {
		t.Fatal("no life probe")
	}
	waitLong(t, waiting, 3*time.Second)
	f.s.balancer.heal.freeze()
	waitLong(t, func() bool { return !waiting() && !track.lifeBusy.Load() }, 3*time.Second)
	if f.nodes["n"].probes.Load() != 0 || q.inFlight() != rrQueueCap {
		t.Fatal("withdrawn flight started or leaked its reservation")
	}
}

func TestB50RRMultiCancellationHoldsPhysicalPlaces(t *testing.T) {
	f := newHealFixture(t, []string{"n"}, []string{"n"}, 0)
	f.g.links = rrMultiLinks(f)
	// The fake dial deliberately ignores cancellation during this sleep.
	f.nodes["n"].slow = 600*time.Millisecond
	q := f.g.rrQueue()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan rrProbe, 1)
	go func() { done <- f.g.rrSelfProbe(ctx, f.nodes["n"], time.Time{}, false) }()
	waitLong(t, func() bool { return f.nodes["n"].active.Load() == 3 }, 3*time.Second)
	cancel()
	select {
	case got := <-done:
		if !got.cancelled() {
			t.Fatalf("cancelled flight: %+v", got)
		}
	case <-time.After(3*time.Second):
		t.Fatal("waiter failed to cancel")
	}
	if q.inFlight() != 3 {
		t.Fatalf("released reservations before physical probes returned: %d", q.inFlight())
	}
	waitLong(t, func() bool { return q.inFlight() == 0 }, 3*time.Second)
}
