package urltest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
)

type warmupTestLeaf struct {
	adapter.Outbound
	tag string
	run func(context.Context) error
}

func (n *warmupTestLeaf) Tag() string { return n.tag }
func (n *warmupTestLeaf) Type() string { return C.TypeVLESS }
func (n *warmupTestLeaf) IPWarmupEligible() bool { return true }
func (n *warmupTestLeaf) WarmAuthenticatedIP(ctx context.Context) error {
	if n.run == nil { return nil }
	return n.run(ctx)
}

type warmupTestGroup struct {
	adapter.OutboundGroup
	tag, kind string
	selected adapter.Outbound
	all []string
}

func (g *warmupTestGroup) Tag() string { return g.tag }
func (g *warmupTestGroup) Type() string { return g.kind }
func (g *warmupTestGroup) Selected(string) adapter.Outbound { return g.selected }
func (g *warmupTestGroup) All() []string { return g.all }

type warmupTestManager struct {
	adapter.OutboundManager
	nodes []adapter.Outbound
}

func (m *warmupTestManager) Outbounds() []adapter.Outbound { return m.nodes }
func (m *warmupTestManager) Default() adapter.Outbound { return nil }
func (m *warmupTestManager) Outbound(tag string) (adapter.Outbound, bool) {
	for _, node := range m.nodes {
		if node.Tag() == tag { return node, true }
	}
	return nil, false
}

func warmupTestGraph(n int, run func(context.Context) error) (*warmupTestManager, map[string]bool) {
	m := &warmupTestManager{}
	reachable := make(map[string]bool)
	for i := 0; i < n; i++ {
		leaf := &warmupTestLeaf{tag: fmt.Sprintf("leaf-%d", i), run: run}
		group := &warmupTestGroup{tag: fmt.Sprintf("group-%d", i), kind: C.TypeURLTest, selected: leaf, all: []string{leaf.tag}}
		m.nodes = append(m.nodes, leaf, group)
		reachable[leaf.tag], reachable[group.tag] = true, true
	}
	return m, reachable
}

func waitWarmupDone(t *testing.T, c *IPWarmupCoordinator) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(3 * time.Second):
		t.Fatal("warmup workers did not drain")
	}
}

func TestLXIPWarmupPriorityAndQueueLimit(t *testing.T) {
	m, reachable := warmupTestGraph(12, nil)
	leaf, _ := m.Outbound("leaf-11")
	selector := &warmupTestGroup{tag: "selector", kind: C.TypeSelector, selected: leaf}
	m.nodes = append(m.nodes, selector)
	reachable[selector.tag] = true
	delete(reachable, "group-0")
	plan := planIPWarmup(m, reachable, []string{"leaf-11", "leaf-0"})
	if len(plan) != 8 || plan[0].Tag() != "leaf-11" || plan[1].Tag() != "leaf-1" {
		t.Fatalf("unexpected plan: len=%d first=%v", len(plan), plan)
	}
	seen := make(map[string]bool)
	for _, node := range plan {
		if seen[node.Tag()] { t.Fatal("duplicate warmup target") }
		seen[node.Tag()] = true
	}
	if seen["leaf-0"] { t.Fatal("recent node displaced a selected reachable group") }
}

func TestLXIPWarmupStartupAndFreshness(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), NewHistoryStorage())
	c := NewIPWarmupCoordinator(ctx)
	defer c.Stop()
	ctx = service.ContextWithPtr(ctx, c)
	finishStartup := BeginIPWarmupStartupProbe(ctx)
	var ran atomic.Int32
	m, reachable := warmupTestGraph(3, func(context.Context) error { ran.Add(1); return nil })
	service.PtrFromContext[HistoryStorage](ctx).StoreURLTestHistory("leaf-0", &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	finishPlan := PlanIPWarmupURLTests(ctx, m, []adapter.Outbound{m.nodes[3]})
	defer finishPlan()
	c.Start(m, func() map[string]bool { return reachable })
	select {
	case <-c.done: t.Fatal("startup barrier was bypassed")
	case <-time.After(30 * time.Millisecond):
	}
	if ran.Load() != 0 { t.Fatal("warmup ran while startup URLTest pending") }
	finishStartup()
	waitWarmupDone(t, c)
	if ran.Load() != 1 { t.Fatalf("fresh or planned URLTest duplicated: %d calls", ran.Load()) }
}

func TestLXIPWarmupWorkerCapAndNetworkCancellation(t *testing.T) {
	ctx := context.Background()
	c := NewIPWarmupCoordinator(ctx)
	defer c.Stop()
	var active, peak, started atomic.Int32
	ready := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func(){ close(release) })
	m, reachable := warmupTestGraph(8, func(ctx context.Context) error {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {}
		started.Add(1)
		ready <- struct{}{}
		<-ctx.Done()
		<-release // late cleanup must still occupy the worker
		return ctx.Err()
	})
	c.Start(m, func() map[string]bool { return reachable })
	for i := 0; i < 2; i++ {
		select { case <-ready: case <-time.After(time.Second): t.Fatal("worker did not start") }
	}
	c.NetworkChanged()
	select {
	case <-c.done: t.Fatal("released workers before cleanup")
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func(){ close(release) })
	waitWarmupDone(t, c)
	if started.Load() != 2 || peak.Load() != 2 || active.Load() != 0 {
		t.Fatalf("invalid cap/cancellation: started=%d peak=%d active=%d", started.Load(), peak.Load(), active.Load())
	}
}

func TestLXIPWarmupForegroundNeverWaitsAndCancelsDuplicate(t *testing.T) {
	c := NewIPWarmupCoordinator(context.Background())
	defer c.Stop()
	ready := make(chan struct{})
	cancelled := make(chan struct{})
	m, reachable := warmupTestGraph(1, func(ctx context.Context) error {
		close(ready)
		<-ctx.Done()
		close(cancelled)
		return ctx.Err()
	})
	c.Start(m, func() map[string]bool { return reachable })
	select { case <-ready: case <-time.After(time.Second): t.Fatal("worker did not start") }
	finish := c.BeginUse("leaf-0")
	defer finish()
	select { case <-cancelled: case <-time.After(time.Second): t.Fatal("foreground did not cancel duplicate") }
	waitWarmupDone(t, c)
}

func TestLXIPWarmupSelectionChangeStopsQueuedWork(t *testing.T) {
	c := NewIPWarmupCoordinator(context.Background())
	defer c.Stop()
	var started atomic.Int32
	ready := make(chan struct{}, 8)
	m, reachable := warmupTestGraph(8, func(ctx context.Context) error {
		started.Add(1)
		ready <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	})
	c.Start(m, func() map[string]bool { return reachable })
	for i := 0; i < 2; i++ {
		select { case <-ready: case <-time.After(time.Second): t.Fatal("worker did not start") }
	}
	c.SelectionChanged()
	waitWarmupDone(t, c)
	if started.Load() != 2 { t.Fatalf("stale selection scheduled more work: %d", started.Load()) }
}
