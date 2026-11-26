// lx:begin reachability-walk
package route

import (
	"github.com/sagernet/sing-box/adapter"
	R "github.com/sagernet/sing-box/route/rule"
)

// The pure reachability walk (SPEC 020) is compiled into EVERY build, not only
// with `with_lx_idle_suspend`: IP warmup (b41 F1, peer review #10) needs
// IPWarmupReachableTags on Windows, where the mobile idle-suspend tag is
// deliberately not built in. Only the idle tick and the CACHED reachability
// (reachability_lx.go, behind the tag) are mobile-specific; the uncached walk
// below is plain routing-graph traversal with no platform assumptions.

// reachableActiveTags is the narrow capability a urltest group exposes so the
// walk can descend into its WHOLE current pool (round_robin), not just Now().
// Implemented by *group.URLTest; kept as an interface so route does not import
// protocol/group.
type reachableActiveTags interface {
	ActiveTags() []string
}

// IPWarmupReachableTags uses the actual routing graph even when idle suspend
// is disabled. The speculative scheduler must never assume all tags are active.
func (r *Router) IPWarmupReachableTags() map[string]bool {
	return r.computeReachable()
}

func (r *Router) computeReachable() map[string]bool {
	return r.computeReachability().reachable
}

// computeReachability runs the walk from the seeds: final and rule targets are
// manual roots, DNS-server detours auto ones.
func (r *Router) computeReachability() reachability {
	var seeds []string
	if def := r.outbound.Default(); def != nil {
		seeds = append(seeds, def.Tag())
	}
	for _, rule := range r.rules {
		seeds = append(seeds, ruleOutboundTags(rule)...)
	}
	// A DNS-server detour is dialable at any moment (every resolution goes
	// through it), so it is "traffic can currently reach it" by definition. Not
	// seeding it made a DNS-only WG endpoint flap Down/Up around every quiet gap,
	// adding a wake handshake to the first resolution of each browsing session.
	var dnsSeeds []string
	if r.dnsTransport != nil {
		for _, transport := range r.dnsTransport.Transports() {
			if tag := transport.OutboundTag(); tag != "" {
				dnsSeeds = append(dnsSeeds, tag)
			}
		}
	}
	return walkReachability(seeds, dnsSeeds, r.outbound.Outbound)
}

// reachability is the result of one walk: the reachable set and the incoming
// edge counts per tag.
type reachability struct {
	reachable map[string]bool
	refs      map[string]selectionRefs
}

// reachableSet is the pure reachability walk, decoupled from *Router so it is
// unit-testable with a stub resolver. seeds are the entry tags (final + rule
// targets); resolve looks a tag up to an outbound (the second return is false
// for an unknown tag).
func reachableSet(seeds []string, resolve func(tag string) (adapter.Outbound, bool)) map[string]bool {
	return walkReachability(seeds, nil, resolve).reachable
}

// walkReachability walks from the manual seeds (final, rule targets) and the
// auto seeds (DNS-server detours), marking reachable tags and counting every
// edge that leads into a tag by class.
func walkReachability(manualSeeds []string, autoSeeds []string, resolve func(tag string) (adapter.Outbound, bool)) reachability {
	result := reachability{
		reachable: make(map[string]bool),
		refs:      make(map[string]selectionRefs),
	}
	for _, seed := range manualSeeds {
		walkReachable(seed, true, &result, resolve)
	}
	for _, seed := range autoSeeds {
		walkReachable(seed, false, &result, resolve)
	}
	return result
}

// ruleOutboundTags extracts the outbound tag(s) a rule's action routes to. Only
// route/bypass actions carry an outbound; everything else (reject, sniff, dns,
// resolve, hijack-dns) routes nowhere and contributes no seed.
func ruleOutboundTags(rule adapter.Rule) []string {
	switch action := rule.Action().(type) {
	case *R.RuleActionRoute:
		if action.Outbound != "" {
			return []string{action.Outbound}
		}
	case *R.RuleActionBypass:
		if action.Outbound != "" {
			return []string{action.Outbound}
		}
	}
	return nil
}

// walkReachable counts the edge that led here (manual or auto), marks tag
// reachable and descends into whatever tag actively routes through right now,
// transitively. The edge is counted BEFORE the visited check, so every incoming
// edge counts once; reachable (== the visited set) guards against cycles and
// keeps each tag's own edges from being expanded twice.
//
// Edge classes (SPEC 097): a selector's current choice is manual; a urltest
// pool member, a static dependency (detour, chain position) and a DNS-server
// detour are auto. No weight is inherited: selector в†’ urltest в†’ X gives X one
// auto edge, not a manual one.
func walkReachable(tag string, manual bool, result *reachability, resolve func(tag string) (adapter.Outbound, bool)) {
	if tag == "" {
		return
	}
	counted := result.refs[tag]
	if manual {
		counted.manual++
	} else {
		counted.auto++
	}
	result.refs[tag] = counted
	if result.reachable[tag] {
		return
	}
	result.reachable[tag] = true

	outbound, loaded := resolve(tag)
	if !loaded {
		return
	}

	// A urltest group routes through its WHOLE active pool (round_robin) or its
	// single current node (legacy). Descend into all of them.
	if active, ok := outbound.(reachableActiveTags); ok {
		for _, child := range active.ActiveTags() {
			walkReachable(child, false, result, resolve)
		}
		return
	}

	// A selector routes through its single current choice only вЂ” Now(), NOT All()
	// (a non-selected member is exactly what we want to be able to suspend).
	if group, ok := outbound.(adapter.OutboundGroup); ok {
		walkReachable(adapter.GroupNow(group), true, result, resolve)
		return
	}

	// An ordinary outbound routes through its static detour dependencies (a
	// chain lists its top hop, a chain hop its position and the hop below).
	for _, dependency := range outbound.Dependencies() {
		walkReachable(dependency, false, result, resolve)
	}
}

// lx:end reachability-walk
