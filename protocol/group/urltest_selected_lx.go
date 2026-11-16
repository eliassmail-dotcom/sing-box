package group

import "github.com/sagernet/sing-box/adapter"

// selectedOutboundTCP and selectedOutboundUDP have exactly one lock domain.
// Keep readers off updateAccess: it can be held during a network probe.
func (g *URLTestGroup) selectedLx() (tcp, udp adapter.Outbound) {
	g.selectedAccess.RLock()
	defer g.selectedAccess.RUnlock()
	return g.selectedOutboundTCP, g.selectedOutboundUDP
}

func (g *URLTestGroup) setSelectedTCPLx(outbound adapter.Outbound) {
	g.selectedAccess.Lock()
	g.selectedOutboundTCP = outbound
	g.selectedAccess.Unlock()
}

func (g *URLTestGroup) setSelectedUDPLx(outbound adapter.Outbound) {
	g.selectedAccess.Lock()
	g.selectedOutboundUDP = outbound
	g.selectedAccess.Unlock()
}

// updateSelectedLx atomically checks and updates one network's selected
// outbound. It returns the previous value, whether the update was accepted,
// and whether the selected node actually changed.
func (g *URLTestGroup) updateSelectedLx(network string, outbound adapter.Outbound, exists bool) (previous adapter.Outbound, applied bool, changed bool) {
	g.selectedAccess.Lock()
	defer g.selectedAccess.Unlock()
	switch network {
	case "tcp":
		previous = g.selectedOutboundTCP
	case "udp":
		previous = g.selectedOutboundUDP
	default:
		return nil, false, false
	}
	if previous == nil || ((exists || !g.guardAllows(RealTag(previous, network))) && outbound != previous) {
		applied = true
		changed = previous != outbound
		if changed {
			if network == "tcp" {
				g.selectedOutboundTCP = outbound
			} else {
				g.selectedOutboundUDP = outbound
			}
		}
	}
	return previous, applied, changed
}

// SelectsPerConnectionLx tells the router to hand a routed connection to this
// group instead of the node Selected reports: the pick, penalties and the
// in-connection fallback run in DialContext.
func (s *URLTest) SelectsPerConnectionLx() {}
