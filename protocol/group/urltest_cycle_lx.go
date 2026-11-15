package group

// LX explicit "next node" command. It changes the selected route within the
// active URLTest policy without replacing the Strategy selector or modifying
// subscribed configuration. In a priority group we recurse only into the
// currently chosen (base or white) tier: tapping Smart never promotes white
// while base is alive.
//
// Existing connections are deliberately left intact (selector_interrupt=false).
// The new node is held for a short period unless health probes/dials fail.

import (
	"errors"
	"sort"
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

const (
	// LXNextNodeTag is reserved for SelectOutbound RPC when groupTag names an
	// LX URLTest (the RPC's existing protobuf fields remain unchanged).
	LXNextNodeTag    = "__lx_next_node__"
	lxManualNodeHold = 30 * time.Second
	lxCycleMaxDepth  = 12
)

var (
	ErrLXNoAlternative = errors.New("no other healthy node in the selected mode")
	ErrLXRoundRobin    = errors.New("round_robin assigns nodes per connection; manual node change is unavailable")
	ErrLXNotRunning    = errors.New("URLTest group is not running")
)

type lxManualHold struct {
	tag   string
	until time.Time
}

type lxCycleCandidate struct {
	node    adapter.Outbound
	realTag string
	delay   uint16
	penalty int64
}

// CycleNode selects a different healthy leaf within this URLTest group. A
// nested base/white URLTest retains the higher-level priority selector.
func (s *URLTest) CycleNode() (string, error) {
	if s.group == nil {
		return "", ErrLXNotRunning
	}
	return s.group.cycleNode(0)
}

func (g *URLTestGroup) cycleNode(depth int) (string, error) {
	if depth >= lxCycleMaxDepth {
		return "", errors.New("URLTest nesting exceeds safety limit")
	}
	g.updateAccess.Lock()
	defer g.updateAccess.Unlock()

	if g.balancer != nil {
		return "", ErrLXRoundRobin
	}
	if g.history == nil {
		return "", ErrLXNotRunning
	}

	// Prefer the true live route, not a stale cached pointer to the previous
	// tier. This is important for Smart base -> white -> base recovery.
	tcp, _ := g.selectedLx()
	current := tcp
	if len(g.priorityOutbounds) > 0 {
		current, _ = g.selectPriority(N.NetworkTCP)
	} else if current == nil {
		current, _ = g.Select(N.NetworkTCP)
	}

	// The normal Smart route is a nested URLTest (base or white). Rotate its
	// leaf only; never replace a working base group with white on a user tap.
	if nested, ok := current.(*URLTest); ok {
		if nested.group == nil {
			return "", ErrLXNotRunning
		}
		return nested.group.cycleNode(depth + 1)
	}

	var currentRealTag string
	if current != nil {
		currentRealTag = RealTag(current, N.NetworkTCP)
	}
	allowedTier := false
	if len(g.priorityOutbounds) > 0 && current != nil {
		allowedTier = g.priorityOutbounds[current.Tag()]
	}
	candidates := make([]lxCycleCandidate, 0, len(g.outbounds))
	seen := make(map[string]bool, len(g.outbounds))
	for _, node := range g.outbounds {
		if !supportsNetwork(node, N.NetworkTCP) {
			continue
		}
		if len(g.priorityOutbounds) > 0 && g.priorityOutbounds[node.Tag()] != allowedTier {
			continue
		}
		realTag := RealTag(node, N.NetworkTCP)
		if realTag == "" || seen[realTag] || !g.selectionNodeEligible(node, N.NetworkTCP) {
			continue
		}
		history := g.history.LoadURLTestHistory(realTag)
		if history == nil {
			continue
		}
		seen[realTag] = true
		candidates = append(candidates, lxCycleCandidate{
			node: node, realTag: realTag, delay: history.Delay,
			penalty: g.penaltyOf(realTag),
		})
	}
	if len(candidates) < 1 {
		return "", ErrLXNoAlternative
	}

	// Stable, deterministic cycle through reachable nodes: lowest penalties,
	// then ascending RTT, then the tag. Repeated taps walk beyond #2.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if a.penalty != b.penalty {
			return a.penalty < b.penalty
		}
		if a.delay != b.delay {
			return a.delay < b.delay
		}
		return a.realTag < b.realTag
	})
	currentIndex := -1
	for i, candidate := range candidates {
		if candidate.realTag == currentRealTag {
			currentIndex = i
			break
		}
	}
	next := candidates[(currentIndex+1)%len(candidates)]
	if next.realTag == currentRealTag {
		return "", ErrLXNoAlternative
	}

	g.setSelectedTCPLx(next.node)
	g.noteSelectionChange(N.NetworkTCP)
	// Keep UDP aligned when the new node supports it. Do not discard a working
	// UDP route in a mixed TCP-only/UDP-capable group.
	if supportsNetwork(next.node, N.NetworkUDP) {
		g.setSelectedUDPLx(next.node)
		g.noteSelectionChange(N.NetworkUDP)
	}
	g.manualHold.Store(&lxManualHold{tag: next.realTag, until: time.Now().Add(lxManualNodeHold)})
	g.logger.Info("lx manual next node: ", currentRealTag, " -> ", next.realTag)
	// Refresh the reachability graph and UI. Do not interrupt live streams.
	invalidateReachability(g.ctx)
	g.history.NotifyUpdated()
	return next.realTag, nil
}
