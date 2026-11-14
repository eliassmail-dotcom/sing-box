package group

// LX adaptive hysteresis for least_test. The legacy tolerance remains unchanged
// until tolerance_percent is explicitly enabled. The existing absolute tolerance
// then becomes a ceiling; the percentage threshold adapts to the current RTT,
// with a 20 ms floor to avoid switching on tiny fluctuations.
//
// Minimum hold applies only to healthy current selections. Losing URLTest
// history, a path-dead dial, or a priority-tier change must bypass the hold.

import (
	"time"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

func (g *URLTestGroup) probeLinks() []string {
	if len(g.links) > 0 {
		return g.links
	}
	return []string{g.link}
}

func (g *URLTestGroup) fasterEnough(current, candidate uint16) bool {
	if current == 0 {
		return true
	}
	if candidate >= current {
		return false
	}
	threshold := uint32(g.tolerance)
	if g.tolerancePercent > 0 {
		relative := (uint32(current)*uint32(g.tolerancePercent) + 99) / 100
		if relative < 20 {
			relative = 20
		}
		if relative < threshold {
			threshold = relative
		}
	}
	return uint32(candidate)+threshold < uint32(current)
}

func (g *URLTestGroup) holdSelected(network string, current adapter.Outbound) bool {
	if g.minHold <= 0 || current == nil {
		return false
	}
	var last int64
	switch network {
	case N.NetworkTCP:
		last = g.lastSwitchTCP.Load()
	case N.NetworkUDP:
		last = g.lastSwitchUDP.Load()
	}
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) < g.minHold
}

func (g *URLTestGroup) noteSelectionChange(network string) {
	switch network {
	case N.NetworkTCP:
		g.lastSwitchTCP.Store(time.Now().UnixNano())
	case N.NetworkUDP:
		g.lastSwitchUDP.Store(time.Now().UnixNano())
	}
}
