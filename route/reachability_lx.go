//go:build with_lx_idle_suspend

// lx:begin idle-suspend
package route

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service/pause"
)

// idleTickFloor is the minimum idle-tick period: however small the configured
// threshold, never poll more often than this (the tick itself is a power cost).
const idleTickFloor = 5 * time.Second

// idleTickDivisor sets the tick period to threshold/divisor, so an endpoint is
// caught crossing into "idle for XX" within ~half a window rather than a full one.
const idleTickDivisor = 2

// SPEC 020 — reachability from the active routing tree.
//
// An outbound is "reachable" if traffic can currently reach it: it is the final
// outbound, the target of a routing rule, the active choice of a selector on a
// reachable path, a member of a reachable urltest's current pool, or detoured-to
// (transitively) by any of the above. Idle-suspend (the router idle tick) only
// suspends WG/AWG endpoints that are NOT in this set — an endpoint nothing can
// currently route to.
//
// The reachable set is recomputed EVENT-DRIVEN, not every tick: it only changes
// when the active routing tree changes — a selector switch (SelectOutbound), a
// urltest auto-switch / pool rebuild (setSlots), or a config reload. Each of
// those calls InvalidateReachability(), which marks the cache dirty; the next
// idle tick recomputes the walk once and caches it. Between events the tick reads
// the cached map and does a single idle comparison per endpoint — no walk.

// reachableOutbounds returns the cached reachable set, recomputing the walk only
// when it is dirty (initial state, or after an event). The walk is NOT run under
// the cache lock — it calls into the outbound manager and groups, which take
// their own locks; holding ours across that risks a lock-order deadlock with an
// event point that invalidates while holding a group lock. So: compute outside
// the lock, then publish under it.
func (r *Router) reachableOutbounds() map[string]bool {
	reachable, _ := r.reachability()
	return reachable
}

// reachability returns the cached walk: the reachable set and, per tag, the
// incoming edges counted by class (SPEC 097). Both come from the same walk and
// share the dirty flag.
func (r *Router) reachability() (map[string]bool, map[string]selectionRefs) {
	if !r.reachDirty.Load() {
		r.reachMu.RLock()
		cached, cachedRefs := r.reachCache, r.reachRefs
		r.reachMu.RUnlock()
		if cached != nil {
			return cached, cachedRefs
		}
	}
	// Dirty (or first call): recompute outside any lock. Clear the flag BEFORE the
	// walk so a concurrent event during the walk re-dirties us (we recompute next
	// tick) rather than being lost.
	r.reachDirty.Store(false)
	fresh := r.computeReachability()
	r.reachMu.Lock()
	r.reachCache = fresh.reachable
	r.reachRefs = fresh.refs
	r.reachMu.Unlock()
	return fresh.reachable, fresh.refs
}

// computeReachable and the whole uncached walk (ruleOutboundTags, walkReachability,
// reachability struct) live in reachability_walk_lx.go, which is compiled in every
// build: IP warmup (b41 F1) uses IPWarmupReachableTags on Windows too, where the
// mobile idle-suspend tag is not built in (peer review #10).

// SelectionRefs implements adapter.ReachabilityReporter (SPEC 097): the
// incoming edges into tag from the cached walk. Computed whether or not the
// idle tick runs — lx.wg.idle.build_max works without lx.wg.idle.suspend; the event
// points invalidate the cache either way.
func (r *Router) SelectionRefs(tag string) (manual int, auto int) {
	_, refs := r.reachability()
	counted := refs[tag]
	return counted.manual, counted.auto
}

// startIdleSuspend launches the idle-suspend tick goroutine. No-op (nil error)
// when the feature is disabled (idleSuspend == 0) — zero overhead. Built only
// with `with_lx_idle_suspend`; the stub build (idle_suspend_stub_lx.go) returns
// an explicit error if the option is set without the tag. Signature returns error
// for symmetry with that stub.
//
// The ticker is registered with the pause.Manager (like the urltest ticker): a
// paused device (screen off / no network) already has every WG device Down'd by
// the pause callbacks, so ticking through the pause is pure waste.
//
// The prerequisite checks repeat option.ResolveLX (SPEC 098), which box.New runs
// first; they stay as a guard for routers built outside box.New.
func (r *Router) startIdleSuspend() error {
	if r.idleSuspend <= 0 {
		if r.idleSuspendReachable > 0 {
			return E.New("lx.wg.idle.suspend_reachable requires lx.wg.idle.suspend")
		}
		if r.idleTeardownSet {
			return E.New("lx.wg.idle.teardown requires lx.wg.idle.suspend")
		}
		return nil
	}
	if r.idleSuspendReachable > 0 && r.idleSuspendReachable < r.idleSuspend {
		return E.New("lx.wg.idle.suspend_reachable must be >= lx.wg.idle.suspend")
	}
	r.idleStop = make(chan struct{})
	period := r.idleSuspend / idleTickDivisor
	if period < idleTickFloor {
		period = idleTickFloor
	}
	ticker := time.NewTicker(period)
	if r.pauseManager != nil {
		r.idlePauseCallback = pause.RegisterTicker(r.pauseManager, ticker, period, nil)
	}
	// The stop channel is passed by value: stopIdleSuspend closes and nils the
	// FIELD, and re-reading the field from the loop would race (a nil channel
	// blocks forever, leaking the goroutine and the ticker).
	go r.idleSuspendLoop(ticker, r.idleStop)
	return nil
}

// stopIdleSuspend stops the idle-suspend tick goroutine, if running.
func (r *Router) stopIdleSuspend() {
	if r.idlePauseCallback != nil {
		r.pauseManager.UnregisterCallback(r.idlePauseCallback)
		r.idlePauseCallback = nil
	}
	if r.idleStop != nil {
		close(r.idleStop)
		r.idleStop = nil
	}
}

// idleSuspendLoop ticks every period. Each tick fetches the reachable set (from
// cache — the walk only re-runs when an event invalidated it, never per tick) and
// asks each WG/AWG endpoint to suspend itself if it is unreachable AND idle past
// the threshold. Per endpoint this is a single map lookup + an atomic idle
// comparison; the endpoint owns the suspend/CAS/log decision.
func (r *Router) idleSuspendLoop(ticker *time.Ticker, stop <-chan struct{}) {
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			r.suspendIdleEndpoints(r.reachableOutbounds())
		}
	}
}

// OutboundReachable implements adapter.ReachabilityReporter: whether traffic can
// currently reach the outbound with this tag. With the feature off (no tick, no
// suspends) it reports true so callers (the urltest probe gate) never gate.
func (r *Router) OutboundReachable(tag string) bool {
	if r.idleSuspend <= 0 {
		return true
	}
	return r.reachableOutbounds()[tag]
}

// suspendIdleEndpoints runs one tick's per-endpoint suspend decision over every
// IdleSuspendable in the box, given the reachable set.
//
// WG/AWG endpoints live in the ENDPOINT manager, not the outbound manager —
// outbound.Outbounds() never lists them (it returns only m.outbounds; the
// endpoint fallback exists for Outbound(tag) lookups, not the iteration). So the
// tick MUST iterate r.endpoint.Endpoints() to reach them. Outbounds() is also
// scanned for completeness (a future non-endpoint IdleSuspendable, and to keep the
// contract honest), but with no IdleSuspendable outbounds today it is a no-op.
func (r *Router) suspendIdleEndpoints(reachable map[string]bool) {
	suspend := func(suspendable adapter.IdleSuspendable) {
		suspendable.SuspendIfIdle(reachable[suspendable.Tag()], r.idleSuspend, r.idleSuspendReachable)
		// lx: SPEC 020 level 3 — same tick, after the suspend decision: an endpoint
		// that has now been asleep past the teardown window is released entirely.
		// Ordering matters — an endpoint that just fell asleep has slept ~0s, so it
		// is never torn down in the same tick it was suspended.
		suspendable.TeardownIfSlept(r.idleTeardown)
	}
	if r.endpoint != nil {
		for _, endpoint := range r.endpoint.Endpoints() {
			if suspendable, ok := endpoint.(adapter.IdleSuspendable); ok {
				suspend(suspendable)
			}
		}
	}
	for _, outbound := range r.outbound.Outbounds() {
		if suspendable, ok := outbound.(adapter.IdleSuspendable); ok {
			suspend(suspendable)
		}
	}
}

// lx:end idle-suspend
