package group

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

// Store explicit probe history: a user action must rotate among nodes that
// already passed a health check, without triggering a mass URLTest.
func lxAlive(g *URLTestGroup, tag string, delay uint16) {
	g.history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
}

func TestLXCycleNextNodeRotatesAndHolds(t *testing.T) {
	a, b, c := newFailoverNode("a", 0), newFailoverNode("b", 0), newFailoverNode("c", 0)
	g := newFailoverTestGroup(t, a, b, c)
	g.failover = false
	g.tolerance = 175
	g.setSelectedTCPLx(a)
	g.setSelectedUDPLx(a)
	lxAlive(g, "a", 40)
	lxAlive(g, "b", 70)
	lxAlive(g, "c", 90)
	for _, want := range []string{"b", "c", "a"} {
		got, err := g.cycleNode(0)
		if err != nil || got != want {
			t.Fatalf("expected next node %s: got %s, err %v", want, got, err)
		}
		current, udp := g.selectedLx()
		if current.Tag() != want || udp.Tag() != want {
			t.Fatalf("manual rotation must update TCP and UDP, got %s/%s", current.Tag(), udp.Tag())
		}
		if selection, _ := g.Select(N.NetworkTCP); selection.Tag() != want {
			t.Fatalf("manual node must not immediately revert to fastest; got %s", selection.Tag())
		}
	}
	// Natural automatic selection resumes after the manual hold expires.
	g.manualHold.Store(&lxManualHold{tag: "a", until: time.Now().Add(-time.Second)})
	g.lastSwitchTCP.Store(time.Now().Add(-time.Minute).UnixNano())
	if selection, _ := g.Select(N.NetworkTCP); selection != a {
		t.Fatal("normal automatic selection should resume after hold")
	}
}

func TestLXCycleNoHealthyAlternative(t *testing.T) {
	a, b := newFailoverNode("a", 0), newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	g.failover = false
	g.setSelectedTCPLx(a)
	lxAlive(g, "a", 60)
	_, err := g.cycleNode(0)
	if !errors.Is(err, ErrLXNoAlternative) {
		t.Fatalf("expected ErrLXNoAlternative, got %v", err)
	}
	if selected, _ := g.selectedLx(); selected != a {
		t.Fatal("failed rotate must leave selection intact")
	}
}

func TestLXCycleAvoidsQuarantinedAlternative(t *testing.T) {
	a, b := newFailoverNode("a", 0), newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	g.failover = false
	g.passiveGuard = newLXPassiveGuard()
	g.setSelectedTCPLx(a)
	lxAlive(g, "a", 60)
	lxAlive(g, "b", 40)
	for _, site := range []string{"site1", "site2", "site3"} {
		g.passiveGuard.record("b", true, site)
	}
	_, err := g.cycleNode(0)
	if !errors.Is(err, ErrLXNoAlternative) {
		t.Fatalf("manual next-node must not select quarantined leaf: %v", err)
	}
	if selected, _ := g.selectedLx(); selected != a {
		t.Fatal("manual cycling altered the working leaf")
	}
}

func TestLXCycleDeadCurrentToOnlyLiveAlternative(t *testing.T) {
	dead, alive := newFailoverNode("dead", 0), newFailoverNode("alive", 0)
	g := newFailoverTestGroup(t, dead, alive)
	g.failover = false
	g.setSelectedTCPLx(dead)
	lxAlive(g, "alive", 110)
	got, err := g.cycleNode(0)
	if err != nil || got != "alive" {
		t.Fatalf("must replace dead cached node with sole live alternative: %s %v", got, err)
	}
	if selected, _ := g.selectedLx(); selected != alive {
		t.Fatal("cached selection must move to the healthy node")
	}
}

func lxNestedURLTest(t *testing.T, tag string, nodes ...*failoverNode) (*URLTest, *URLTestGroup) {
	t.Helper()
	byTag := make([]string, len(nodes))
	for i, node := range nodes {
		byTag[i] = node.Tag()
	}
	outbound, err := NewURLTest(context.Background(), nil, logger.NOP(), tag, option.URLTestOutboundOptions{Outbounds: byTag})
	if err != nil {
		t.Fatal(err)
	}
	g := newFailoverTestGroup(t, nodes...)
	g.failover = false
	s := outbound.(*URLTest)
	s.group = g
	return s, g
}

func TestLXCycleSmartNeverPromotesWhiteWhileBaseAlive(t *testing.T) {
	a, b := newFailoverNode("a", 0), newFailoverNode("b", 0)
	w1, w2 := newFailoverNode("w1", 0), newFailoverNode("w2", 0)
	base, baseGroup := lxNestedURLTest(t, "base", a, b)
	white, whiteGroup := lxNestedURLTest(t, "white", w1, w2)
	history := urltest.NewHistoryStorage()
	baseGroup.history = history
	whiteGroup.history = history
	baseGroup.setSelectedTCPLx(a)
	whiteGroup.setSelectedTCPLx(w1)
	for tag, delay := range map[string]uint16{"a": 100, "b": 120, "w1": 10, "w2": 15} {
		history.StoreURLTestHistory(tag, &adapter.URLTestHistory{Time: time.Now(), Delay: delay})
	}
	parent := &URLTestGroup{
		ctx: context.Background(), logger: logger.NOP(),
		outbounds: []adapter.Outbound{base, white}, history: history,
		lxURLTestGroup: lxURLTestGroup{priorityOutbounds: map[string]bool{"base": true}},
	}
	parent.setSelectedTCPLx(base)
	got, err := parent.cycleNode(0)
	if err != nil || got != "b" {
		t.Fatalf("should rotate within base, not white: %s %v", got, err)
	}
	if selected, _ := parent.selectedLx(); selected != base {
		t.Fatal("Smart's selected tier must remain base")
	}
	if selected, _ := whiteGroup.selectedLx(); selected != w1 {
		t.Fatal("Smart rotation must not change the white group")
	}

	// Only after base becomes unhealthy, rotation may use the white group.
	history.DeleteURLTestHistory("a")
	history.DeleteURLTestHistory("b")
	parent.setSelectedTCPLx(white)
	got, err = parent.cycleNode(0)
	if err != nil || got != "w2" {
		t.Fatalf("white may rotate only while base is down: %s %v", got, err)
	}
}

func TestLXCycleRoundRobinNeedsDedicatedPolicy(t *testing.T) {
	a, b := newFailoverNode("a", 0), newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	g.balancer = &balancer{}
	_, err := g.cycleNode(0)
	if !errors.Is(err, ErrLXRoundRobin) {
		t.Fatalf("expected explicit round-robin limitation, got %v", err)
	}
}

func TestB50StaleHealthSelectionDoesNotUndoFallback(t *testing.T) {
	a, b, c := newFailoverNode("a", 0), newFailoverNode("b", 0), newFailoverNode("c", 0)
	g := newFailoverTestGroup(t, a, b, c)
	g.setSelectedTCPLx(a)
	expected := g.selectedForNetworkLx(N.NetworkTCP)
	g.moveSelection(N.NetworkTCP, b)
	if _, applied := g.updateSelectedLx(N.NetworkTCP, expected, c, true); applied {
		t.Fatal("an older health snapshot must not overwrite a successful dial fallback")
	}
	if got := g.selectedForNetworkLx(N.NetworkTCP); got != b {
		t.Fatalf("want fallback b, got %v", got)
	}
}

func TestB54PriorityProviderPairRetainsFailoverAndTier(t *testing.T) {
	a, backup := newFailoverNode("primary", 0), newFailoverNode("backup", 0)
	pair, child := lxNestedURLTest(t, "provider", a, backup)
	child.failover = true
	white := newFailoverNode("white", 0)
	history := urltest.NewHistoryStorage()
	child.history = history
	child.setSelectedTCPLx(a)
	parent := &URLTestGroup{
		ctx: context.Background(), logger: logger.NOP(),
		outbounds: []adapter.Outbound{pair, white}, history: history,
		lxURLTestGroup: lxURLTestGroup{priorityOutbounds: map[string]bool{"provider": true}},
	}
	for tag, delay := range map[string]uint16{"primary": 150, "backup": 20, "white": 5} {
		lxAlive(parent, tag, delay)
	}
	if got, _ := parent.selectPriority(N.NetworkTCP); got != pair || RealTag(got, N.NetworkTCP) != "primary" {
		t.Fatal("a faster backup must not displace a healthy held variant")
	}
	history.DeleteURLTestHistory("primary")
	if got, _ := parent.selectPriority(N.NetworkTCP); got != pair || RealTag(got, N.NetworkTCP) != "backup" {
		t.Fatal("a live backup must keep the logical node in the preferred tier")
	}
	if got := child.pickForDialNode(N.NetworkTCP); got != backup {
		t.Fatal("dial and parent health must agree on the selected variant")
	}
	history.DeleteURLTestHistory("backup")
	if got, _ := parent.selectPriority(N.NetworkTCP); got != white {
		t.Fatal("white is allowed only when both preferred variants lack history")
	}
	lxAlive(parent, "backup", 200)
	if got, _ := parent.selectPriority(N.NetworkTCP); got != pair {
		t.Fatal("preferred logical node must recover before white")
	}
}

func TestB54PriorityRotationKeepsProviderVariantsPrivate(t *testing.T) {
	a, backup := newFailoverNode("primary", 0), newFailoverNode("backup", 0)
	pair, child := lxNestedURLTest(t, "provider", a, backup)
	child.failover = true
	peer, white := newFailoverNode("peer", 0), newFailoverNode("white", 0)
	history := urltest.NewHistoryStorage()
	child.history = history
	child.setSelectedTCPLx(a)
	parent := &URLTestGroup{
		ctx: context.Background(), logger: logger.NOP(),
		outbounds: []adapter.Outbound{pair, peer, white}, history: history,
		lxURLTestGroup: lxURLTestGroup{priorityOutbounds: map[string]bool{"provider": true, "peer": true}},
	}
	parent.setSelectedTCPLx(pair)
	for tag, delay := range map[string]uint16{"primary": 100, "backup": 20, "peer": 120, "white": 5} {
		lxAlive(parent, tag, delay)
	}
	if got, err := parent.cycleNode(0); err != nil || got != "peer" {
		t.Fatalf("rotate to another logical candidate, got %s %v", got, err)
	}
	if child.selectedForNetworkLx(N.NetworkTCP) != a {
		t.Fatal("parent rotation must not change the pair's variant")
	}
	if got, err := parent.cycleNode(0); err != nil || got != "primary" {
		t.Fatalf("rotate back to held provider variant, got %s %v", got, err)
	}
	history.DeleteURLTestHistory("primary")
	if !parent.holdSelected(N.NetworkTCP, pair) {
		t.Fatal("manual hold belongs to logical node, not its previous variant")
	}
}
