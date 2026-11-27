// lx:begin SPEC 148 ordered provider failover
package group

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// orderedFailoverNodes returns the URLTest members in priority-tier order.
// Members inside each tier retain their configured outbound order. Probes may
// run concurrently, but selection is never ranked by RTT in this mode.
func (g *URLTestGroup) orderedFailoverNodes(network string) []adapter.Outbound {
	ordered := make([]adapter.Outbound, 0, len(g.outbounds))
	for tier := 0; tier < 3; tier++ {
		for _, detour := range g.outbounds {
			if g.priorityTier(detour.Tag()) == tier && supportsNetwork(detour, network) {
				ordered = append(ordered, detour)
			}
		}
	}
	return ordered
}

func (g *URLTestGroup) orderedFailoverIndex(network string, target adapter.Outbound) int {
	for index, detour := range g.orderedFailoverNodes(network) {
		if detour == target {
			return index
		}
	}
	return -1
}

// selectOrderedFallback selects the first healthy member in configured order.
// Before the first probe, it returns the first eligible member as cold start.
func (g *URLTestGroup) selectOrderedFallback(network string) (adapter.Outbound, bool) {
	ordered := g.orderedFailoverNodes(network)
	for _, detour := range ordered {
		tag := RealTag(detour, N.NetworkTCP)
		if tag == "" || !g.guardAllows(tag) {
			continue
		}
		if g.history.LoadURLTestHistory(tag) != nil {
			return detour, true
		}
	}
	for _, detour := range ordered {
		tag := RealTag(detour, N.NetworkTCP)
		if tag != "" && g.guardAllows(tag) {
			return detour, false
		}
	}
	return nil, false
}

// orderedFailoverDegraded only compares the held node with members that follow
// it in the configured order. A faster reserve cannot displace a healthy
// primary unless the existing 2x suspicion + confirmation + 1.5x move gates pass.
func (g *URLTestGroup) orderedFailoverDegraded(node adapter.Outbound) bool {
	history := g.history.LoadURLTestHistory(RealTag(node, N.NetworkTCP))
	if history == nil {
		return false
	}
	tcp, udp := g.selectedLx()
	for _, network := range []string{N.NetworkTCP, N.NetworkUDP} {
		held := tcp
		if network == N.NetworkUDP {
			held = udp
		}
		if held != node {
			continue
		}
		ordered := g.orderedFailoverNodes(network)
		index := g.orderedFailoverIndex(network, node)
		if index < 0 {
			continue
		}
		for _, candidate := range ordered[index+1:] {
			tag := RealTag(candidate, N.NetworkTCP)
			if tag == "" || !g.guardAllows(tag) {
				continue
			}
			other := g.history.LoadURLTestHistory(tag)
			if other != nil && slowerBy(history.Delay, other.Delay, failoverTriggerNum, failoverTriggerDen) {
				return true
			}
		}
	}
	return false
}

const priorityRecoverySuccesses int32 = 2

func (g *URLTestGroup) resetPriorityRecovery(node adapter.Outbound) {
	if node == nil {
		return
	}
	if tag := RealTag(node, N.NetworkTCP); tag != "" {
		g.priorityRecovery.Store(tag, int32(0))
	}
}

func (g *URLTestGroup) recordPriorityRecovery(node adapter.Outbound, success bool) bool {
	if node == nil {
		return false
	}
	tag := RealTag(node, N.NetworkTCP)
	if tag == "" {
		return false
	}
	if !success {
		g.priorityRecovery.Store(tag, int32(0))
		return false
	}
	var streak int32
	if previous, loaded := g.priorityRecovery.Load(tag); loaded {
		streak, _ = previous.(int32)
	}
	if streak < priorityRecoverySuccesses {
		streak++
	}
	g.priorityRecovery.Store(tag, streak)
	return streak >= priorityRecoverySuccesses
}

func (g *URLTestGroup) priorityRecoveryReady(node adapter.Outbound) bool {
	if node == nil {
		return false
	}
	tag := RealTag(node, N.NetworkTCP)
	if tag == "" {
		return false
	}
	value, loaded := g.priorityRecovery.Load(tag)
	if !loaded {
		return false
	}
	streak, _ := value.(int32)
	return streak >= priorityRecoverySuccesses
}

// priorityFailoverCheck is the ordered variant of SPEC 116/126. It probes the
// held node, confirms sustained degradation with the existing hysteresis, and
// probes only higher-priority members while running on a reserve. Two
// consecutive healthy checks are required before returning to a preferred node.
func (g *URLTestGroup) priorityFailoverCheck(ctx context.Context) map[string]uint16 {
	held := g.failoverHeld()
	result := make(map[string]uint16)
	failed := make(map[string]bool, len(held))
	slow := make(tagSet, len(held))
	recovered := false

	if len(held) > 0 {
		result = g.testNodes(ctx, held, false)
		if ctx.Err() != nil {
			return result
		}
		for _, node := range held {
			if g.history.LoadURLTestHistory(RealTag(node, N.NetworkTCP)) == nil {
				failed[node.Tag()] = true
				g.resetPriorityRecovery(node)
				continue
			}
			if !g.orderedFailoverDegraded(node) {
				continue
			}
			for tag, delay := range g.probeNow(ctx, node) {
				result[tag] = delay
			}
			if ctx.Err() != nil {
				return result
			}
			if g.history.LoadURLTestHistory(RealTag(node, N.NetworkTCP)) == nil {
				failed[node.Tag()] = true
				g.resetPriorityRecovery(node)
			} else if g.orderedFailoverDegraded(node) {
				slow[node.Tag()] = true
				g.resetPriorityRecovery(node)
			}
		}

		// A reserve remains selected while preferred members recover. Probe
		// those members once per health-check cycle; never count two probes in
		// the same cycle as stable recovery.
		recoveryProbed := make(map[string]bool)
		for _, node := range held {
			if failed[node.Tag()] || slow[node.Tag()] {
				continue
			}
			currentIndex := g.orderedFailoverIndex(N.NetworkTCP, node)
			if currentIndex <= 0 {
				continue
			}
			currentHistory := g.history.LoadURLTestHistory(RealTag(node, N.NetworkTCP))
			if currentHistory == nil {
				continue
			}
			ordered := g.orderedFailoverNodes(N.NetworkTCP)
			for _, candidate := range ordered[:currentIndex] {
				candidateTag := RealTag(candidate, N.NetworkTCP)
				if candidateTag == "" {
					continue
				}
				if recoveryProbed[candidateTag] {
					if g.priorityRecoveryReady(candidate) {
						recovered = true
					}
					continue
				}
				recoveryProbed[candidateTag] = true
				if !g.guardAllows(candidateTag) {
					g.resetPriorityRecovery(candidate)
					continue
				}
				for tag, delay := range g.probeNow(ctx, candidate) {
					result[tag] = delay
				}
				if ctx.Err() != nil {
					return result
				}
				candidateHistory := g.history.LoadURLTestHistory(candidateTag)
				if candidateHistory == nil || slowerBy(candidateHistory.Delay, currentHistory.Delay, failoverTriggerNum, failoverTriggerDen) {
					g.resetPriorityRecovery(candidate)
					continue
				}
				if g.recordPriorityRecovery(candidate, true) {
					recovered = true
				}
			}
		}
		if len(failed) == 0 && len(slow) == 0 && !recovered {
			return result
		}
	}

	// Cold start, failure, or confirmed degradation: probe the remaining
	// candidates. Fresh recovery probes are naturally skipped by testNodes.
	if len(held) == 0 || len(failed) > 0 || len(slow) > 0 {
		others := make([]adapter.Outbound, 0, len(g.outbounds))
		for _, detour := range g.outbounds {
			if !failed[detour.Tag()] && !slow[detour.Tag()] {
				others = append(others, detour)
			}
		}
		for tag, delay := range g.testNodes(ctx, others, false) {
			result[tag] = delay
		}
	}
	if ctx.Err() != nil {
		return result
	}
	if len(slow) > 0 {
		g.failoverSlow.Store(&slow)
		defer g.failoverSlow.Store(nil)
	}
	g.performSelectionUpdate(false)
	return result
}

// priorityFailoverSelect keeps the current healthy member, moves only to the
// next healthy member after a confirmed failure/degradation, and returns to a
// higher-priority member only after two consecutive successful checks.
func (g *URLTestGroup) priorityFailoverSelect(network string, reselect bool) (adapter.Outbound, bool) {
	if g.penaltyEmergency(network) {
		if best := g.penaltyBest(network, ""); best != nil {
			return best, true
		}
	}
	if !reselect {
		tcp, udp := g.selectedLx()
		current := tcp
		if network == N.NetworkUDP {
			current = udp
		}
		if current != nil && g.guardAllows(RealTag(current, N.NetworkTCP)) {
			if history := g.history.LoadURLTestHistory(RealTag(current, N.NetworkTCP)); history != nil {
				ordered := g.orderedFailoverNodes(network)
				currentIndex := g.orderedFailoverIndex(network, current)
				if currentIndex >= 0 {
					if slow := g.failoverSlow.Load(); slow != nil && (*slow)[current.Tag()] {
						// Only the first live reserve in configured order may replace
						// a slow node; a faster later reserve cannot leapfrog it.
						for _, candidate := range ordered[currentIndex+1:] {
							candidateTag := RealTag(candidate, N.NetworkTCP)
							if candidateTag == "" || !g.guardAllows(candidateTag) {
								continue
							}
							if candidateHistory := g.history.LoadURLTestHistory(candidateTag); candidateHistory != nil {
								if slowerBy(history.Delay, candidateHistory.Delay, failoverMoveNum, failoverMoveDen) {
									return candidate, true
								}
								break
							}
						}
					}
					// Prefer a recovered higher-priority member only when its
					// latency is no longer materially worse than the held reserve.
					for _, candidate := range ordered[:currentIndex] {
						candidateTag := RealTag(candidate, N.NetworkTCP)
						if candidateTag == "" || !g.guardAllows(candidateTag) || !g.priorityRecoveryReady(candidate) {
							continue
						}
						if candidateHistory := g.history.LoadURLTestHistory(candidateTag); candidateHistory != nil {
							if !slowerBy(candidateHistory.Delay, history.Delay, failoverTriggerNum, failoverTriggerDen) {
								return candidate, true
							}
							g.resetPriorityRecovery(candidate)
						}
					}
				}
				return current, true
			}
		}
	}
	return g.selectOrderedFallback(network)
}

// lx:end SPEC 148 ordered provider failover
