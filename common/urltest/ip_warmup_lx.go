package urltest

import (
	"context"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
)

const (
	ipWarmupQueueLimit = 8
	ipWarmupWorkers    = 2
	ipWarmupBudget     = 6 * time.Second
	ipWarmupFreshTTL   = 10 * time.Minute
)

type ipWarmupTarget interface {
	adapter.Outbound
	IPWarmupEligible() bool
	WarmAuthenticatedIP(context.Context) error
}

type ipWarmupProbeTracker interface {
	BeginIPWarmupProbe() func()
}

type ipWarmupURLTestKey struct{}

// IPWarmupSupportedOS reports whether box.New creates the one-shot
// authenticated IP warmup coordinator (b41 F1). iOS since b40 — the original
// QA scope; Windows since peer review #10: the cycle is platform-neutral (no
// pause manager on desktop simply means no pause-driven early stop, and the
// reachability walk is compiled in every build). Android stays off pending an
// explicit owner decision.
func IPWarmupSupportedOS() bool {
	switch runtime.GOOS {
	case "ios", "windows":
		return true
	}
	return false
}

// One coordinator per iOS Box, no periodic timer. Ordinary URLTests and
// traffic only register intent/cancel optional work; they never wait on slots.
type IPWarmupCoordinator struct {
	ctx            context.Context
	cancel         context.CancelFunc
	mu             sync.Mutex
	startupPending int
	sealed         bool
	startupReady   chan struct{}
	revision       uint64
	waveCancel     context.CancelFunc
	busy           map[string]int
	running        map[string]context.CancelFunc
	recent         []string
	done           chan struct{}
}

func NewIPWarmupCoordinator(ctx context.Context) *IPWarmupCoordinator {
	ctx, cancel := context.WithCancel(ctx)
	return &IPWarmupCoordinator{
		ctx: ctx, cancel: cancel, startupReady: make(chan struct{}),
		busy: make(map[string]int), running: make(map[string]context.CancelFunc),
		done: make(chan struct{}),
	}
}

// Called synchronously by URLTest.PostStart, before spawning its first check.
func BeginIPWarmupStartupProbe(ctx context.Context) func() {
	c := service.PtrFromContext[IPWarmupCoordinator](ctx)
	if c == nil {
		return func() {}
	}
	return c.beginStartupProbe()
}

func (c *IPWarmupCoordinator) beginStartupProbe() func() {
	c.mu.Lock()
	if c.sealed {
		c.mu.Unlock()
		return func() {}
	}
	c.startupPending++
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.startupPending--
			if c.sealed && c.startupPending == 0 {
				close(c.startupReady)
			}
		})
	}
}

func (c *IPWarmupCoordinator) Active() bool { return c != nil && c.ctx.Err() == nil }

func (c *IPWarmupCoordinator) Stop() { c.cancel() }

// A reset before Start is initial network discovery, not an active wave.
// Once sealed, abandon the one-shot cycle; ordinary URLTest handles new links.
func (c *IPWarmupCoordinator) NetworkChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
	c.recent = nil
	if c.sealed {
		c.cancel()
	}
}

// Called from group callbacks under unknown locks: no graph walk, waiting or
// callbacks here. Conservatively discard the remaining old-selection wave.
func (c *IPWarmupCoordinator) SelectionChanged() {
	if !c.Active() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revision++
	if c.waveCancel != nil {
		c.waveCancel()
	}
}

func (c *IPWarmupCoordinator) BeginUse(tag string) func() {
	return c.reserve([]string{tag}, true)
}

func (c *IPWarmupCoordinator) BeginProbe(tag string) func() {
	return c.reserve([]string{tag}, false)
}

func (c *IPWarmupCoordinator) reserve(tags []string, used bool) func() {
	if !c.Active() {
		return func() {}
	}
	c.mu.Lock()
	if c.ctx.Err() != nil {
		c.mu.Unlock()
		return func() {}
	}
	for _, tag := range tags {
		c.busy[tag]++
		if cancel := c.running[tag]; cancel != nil {
			cancel()
		}
		if used {
			for i, old := range c.recent {
				if old == tag {
					c.recent = append(c.recent[:i], c.recent[i+1:]...)
					break
				}
			}
			c.recent = append([]string{tag}, c.recent...)
			if len(c.recent) > ipWarmupQueueLimit {
				c.recent = c.recent[:ipWarmupQueueLimit]
			}
		}
	}
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			for _, tag := range tags {
				c.busy[tag]--
				if c.busy[tag] == 0 {
					delete(c.busy, tag)
				}
			}
		})
	}
}

// Reserve every eligible leaf of the scheduled batch, including nested
// groups. Conservative reservation may suppress extra work; it never changes
// ordinary group freshness or selection. A manual caller's context may not
// contain the box service registry, so on iOS also use the target's tracker.
func PlanIPWarmupURLTests(ctx context.Context, manager adapter.OutboundManager, nodes []adapter.Outbound) func() {
	c := service.PtrFromContext[IPWarmupCoordinator](ctx)
	if (c != nil && !c.Active()) || (c == nil && runtime.GOOS != "ios") {
		return func() {}
	}
	seen := make(map[string]bool)
	var releases []func()
	var walk func(adapter.Outbound)
	walk = func(node adapter.Outbound) {
		if node == nil || seen[node.Tag()] {
			return
		}
		seen[node.Tag()] = true
		if target, ok := node.(ipWarmupTarget); ok && target.IPWarmupEligible() {
			if tracker, ok := target.(ipWarmupProbeTracker); ok {
				releases = append(releases, tracker.BeginIPWarmupProbe())
			} else if c != nil {
				releases = append(releases, c.BeginProbe(node.Tag()))
			}
			return
		}
		if group, ok := node.(adapter.OutboundGroup); ok {
			for _, tag := range group.All() {
				if child, found := manager.Outbound(tag); found {
					walk(child)
				}
			}
		}
	}
	for _, node := range nodes {
		walk(node)
	}
	return func() {
		for _, release := range releases {
			release()
		}
	}
}

func IsIPWarmupURLTest(ctx context.Context) bool {
	value, _ := ctx.Value(ipWarmupURLTestKey{}).(bool)
	return value
}

func beginIPWarmupURLTest(ctx context.Context, detour N.Dialer) (context.Context, func()) {
	c := service.PtrFromContext[IPWarmupCoordinator](ctx)
	if (c != nil && !c.Active()) || (c == nil && runtime.GOOS != "ios") {
		return ctx, func() {}
	}
	ctx = context.WithValue(ctx, ipWarmupURLTestKey{}, true)
	if target, ok := detour.(ipWarmupTarget); ok && target.IPWarmupEligible() {
		if tracker, ok := target.(ipWarmupProbeTracker); ok {
			return ctx, tracker.BeginIPWarmupProbe()
		}
		if c != nil {
			return ctx, c.BeginProbe(target.Tag())
		}
	}
	return ctx, func() {}
}

func (c *IPWarmupCoordinator) Start(manager adapter.OutboundManager, reachable func() map[string]bool) {
	c.mu.Lock()
	if c.sealed {
		c.mu.Unlock()
		return
	}
	c.sealed = true
	if c.startupPending == 0 {
		close(c.startupReady)
	}
	c.mu.Unlock()
	go c.run(manager, reachable)
}

func (c *IPWarmupCoordinator) run(manager adapter.OutboundManager, reachable func() map[string]bool) {
	defer close(c.done)
	defer c.Stop() // no bookkeeping on the hot path once the one-shot cycle drains
	if !c.Active() {
		return
	}
	pm := service.FromContext[pause.Manager](c.ctx)
	if pm != nil {
		cb := pm.RegisterCallback(func(event int) {
			if event == pause.EventDevicePaused || event == pause.EventNetworkPause {
				c.Stop()
			}
		})
		defer pm.UnregisterCallback(cb)
		if pm.IsPaused() {
			return
		}
	}
	select {
	case <-c.ctx.Done():
		return
	case <-c.startupReady:
	}
	if !c.Active() {
		return
	}
	c.mu.Lock()
	revision := c.revision
	recent := append([]string(nil), c.recent...)
	c.mu.Unlock()
	plan := planIPWarmup(manager, reachable(), recent)
	c.mu.Lock()
	if c.ctx.Err() != nil || revision != c.revision {
		c.mu.Unlock()
		return
	}
	wave, cancel := context.WithCancel(c.ctx)
	c.waveCancel = cancel
	c.mu.Unlock()
	defer cancel()
	jobs := make(chan ipWarmupTarget, len(plan))
	for _, target := range plan {
		jobs <- target
	}
	close(jobs)
	var workers sync.WaitGroup
	for i := 0; i < ipWarmupWorkers; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				if wave.Err() != nil {
					return
				}
				c.runTarget(wave, target)
			}
		}()
	}
	workers.Wait()
}

func (c *IPWarmupCoordinator) runTarget(wave context.Context, target ipWarmupTarget) {
	tag := target.Tag()
	history := service.PtrFromContext[HistoryStorage](wave).LoadURLTestHistory(tag)
	if history != nil {
		age := time.Since(history.Time)
		if age >= 0 && age < ipWarmupFreshTTL {
			return
		}
	}
	c.mu.Lock()
	if wave.Err() != nil || c.busy[tag] != 0 || c.running[tag] != nil {
		c.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(wave, ipWarmupBudget)
	c.running[tag] = cancel
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		delete(c.running, tag)
		c.mu.Unlock()
	}()
	_ = target.WarmAuthenticatedIP(ctx)
}

// Selected leaves of reachable selectors, then reachable automatic groups,
// then recently used reachable leaves. Never traverse All() for warmup.
func planIPWarmup(manager adapter.OutboundManager, reachable map[string]bool, recent []string) []ipWarmupTarget {
	if manager == nil || len(reachable) == 0 {
		return nil
	}
	var result []ipWarmupTarget
	seen := make(map[string]bool)
	add := func(node adapter.Outbound) {
		path := make(map[string]bool)
		for node != nil && reachable[node.Tag()] && !path[node.Tag()] {
			path[node.Tag()] = true
			if group, ok := node.(adapter.OutboundGroup); ok {
				node = group.Selected(N.NetworkTCP)
				continue
			}
			if target, ok := node.(ipWarmupTarget); ok && target.IPWarmupEligible() && !seen[node.Tag()] && len(result) < ipWarmupQueueLimit {
				seen[node.Tag()] = true
				result = append(result, target)
			}
			return
		}
	}
	nodes := manager.Outbounds()
	for _, node := range nodes {
		if node != nil && node.Type() == C.TypeSelector {
			add(node)
		}
	}
	if root := manager.Default(); root != nil && root.Type() == C.TypeVLESS {
		add(root)
	}
	for _, node := range nodes {
		if node != nil && node.Type() == C.TypeURLTest {
			add(node)
		}
	}
	for _, tag := range recent {
		if node, ok := manager.Outbound(tag); ok {
			add(node)
		}
	}
	return result
}
