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
		priorityOutbounds: map[string]bool{"base": true},
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
