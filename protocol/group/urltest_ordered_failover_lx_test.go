// lx:begin SPEC 148 ordered provider failover tests
package group

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func newOrderedFailoverTestGroup(t *testing.T, primary string, nodes ...*failoverNode) *URLTestGroup {
	t.Helper()
	g := newFailoverTestGroup(t, nodes...)
	g.priorityOutbounds = map[string]bool{primary: true}
	return g
}

func TestOrderedFailover_coldStartAndFailureUsesConfiguredOrder(t *testing.T) {
	primary := newFailoverNode("primary", 0)
	backup1 := newFailoverNode("backup1", 60*time.Millisecond)
	backup2 := newFailoverNode("backup2", 0)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup1, backup2)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, primary)
	assertSelected(t, g, N.NetworkUDP, primary)

	primary.setErr(context.DeadlineExceeded)
	tick(t, g)

	// backup2 is faster, but the configured first reserve must win.
	assertSelected(t, g, N.NetworkTCP, backup1)
	assertSelected(t, g, N.NetworkUDP, backup1)
}

func TestOrderedFailover_holdsPrimaryInsteadOfRacingFasterBackup(t *testing.T) {
	primary := newFailoverNode("primary", 25*time.Millisecond)
	backup := newFailoverNode("backup", 15*time.Millisecond)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, primary)

	resetDials(primary, backup)
	tick(t, g)

	assertSelected(t, g, N.NetworkTCP, primary)
	assertDials(t, primary, 1)
	assertDials(t, backup, 0)
}

func TestOrderedFailover_transientLatencySpikeDoesNotSwitch(t *testing.T) {
	primary := newFailoverNode("primary", 0)
	backup := newFailoverNode("backup", 0)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	primary.spike.Store(int64(120 * time.Millisecond))
	resetDials(primary, backup)
	tick(t, g)

	assertSelected(t, g, N.NetworkTCP, primary)
	// One suspect sample is confirmed by a second probe; the reserve is not tested.
	assertDials(t, primary, 2)
	assertDials(t, backup, 0)
}

func TestOrderedFailover_confirmedDegradationMovesToNextReserve(t *testing.T) {
	primary := newFailoverNode("primary", 80*time.Millisecond)
	backup1 := newFailoverNode("backup1", 10*time.Millisecond)
	backup2 := newFailoverNode("backup2", 0)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup1, backup2)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, primary)

	tick(t, g)

	// A confirmed >2x degradation permits a move only when the next reserve is
	// at least 1.5x faster. The still-faster second reserve cannot leapfrog it.
	assertSelected(t, g, N.NetworkTCP, backup1)
	assertSelected(t, g, N.NetworkUDP, backup1)
}

func TestOrderedFailover_recoveryRequiresTwoSuccessfulChecks(t *testing.T) {
	primary := newFailoverNode("primary", 0)
	primary.setErr(context.DeadlineExceeded)
	backup := newFailoverNode("backup", 20*time.Millisecond)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, backup)

	primary.setErr(nil)
	tick(t, g)
	assertSelected(t, g, N.NetworkTCP, backup)

	tick(t, g)
	assertSelected(t, g, N.NetworkTCP, primary)
}

func TestOrderedFailover_recoveryWaitsUntilPrimaryIsNoLongerDegraded(t *testing.T) {
	primary := newFailoverNode("primary", 0)
	primary.setErr(context.DeadlineExceeded)
	backup := newFailoverNode("backup", 20*time.Millisecond)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, backup)

	primary.setErr(nil)
	primary.latency = 100 * time.Millisecond
	tick(t, g)
	tick(t, g)
	assertSelected(t, g, N.NetworkTCP, backup)

	primary.latency = 15 * time.Millisecond
	tick(t, g)
	assertSelected(t, g, N.NetworkTCP, backup)
	tick(t, g)
	assertSelected(t, g, N.NetworkTCP, primary)
}

func TestOrderedFailover_dialFailureUsesNextConfiguredMember(t *testing.T) {
	primary := newFailoverNode("primary", 0)
	backup1 := newFailoverNode("backup1", 50*time.Millisecond)
	backup2 := newFailoverNode("backup2", 0)
	g := newOrderedFailoverTestGroup(t, "primary", primary, backup1, backup2)

	if _, err := g.urlTest(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	assertSelected(t, g, N.NetworkTCP, primary)

	primary.setErr(context.DeadlineExceeded)
	g.history.DeleteURLTestHistory("primary")
	conn, fallback, ok := g.penaltyFailoverDial(
		context.Background(), N.NetworkTCP, M.Socksaddr{}, primary, context.DeadlineExceeded,
	)
	if !ok {
		t.Fatal("dial failure must use a live reserve")
	}
	_ = conn.Close()
	if fallback.Tag() != "backup1" {
		t.Fatalf("want first configured reserve backup1, got %s", fallback.Tag())
	}
	assertSelected(t, g, N.NetworkTCP, backup1)
}

func TestOrderedFailover_configAllowsPriorityOutbounds(t *testing.T) {
	outbound, err := NewURLTest(context.Background(), nil, logger.NOP(), "ordered", option.URLTestOutboundOptions{
		Outbounds:        []string{"primary", "backup"},
		Mode:             C.URLTestModeFailover,
		PriorityOutbounds: []string{"primary"},
	})
	if err != nil {
		t.Fatalf("failover with priority_outbounds must be accepted: %v", err)
	}
	if mode := outbound.(*URLTest).Mode(); mode != C.URLTestModeFailover {
		t.Fatalf("Mode() must report failover, got %s", mode)
	}
}
 
// lx:end SPEC 148 ordered provider failover tests
