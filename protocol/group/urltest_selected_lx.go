package group

import (
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
)

// All production writes take selectionWriter; reads are the LX.37 atomic
// values. A stale health check must not overwrite a newer dial fallback.
func (g *URLTestGroup) selectedLx() (tcp, udp adapter.Outbound) {
	return g.selectedOutboundTCP.Load(), g.selectedOutboundUDP.Load()
}

func (g *URLTestGroup) selectionSlotLx(network string) *common.TypedValue[adapter.Outbound] {
	switch network {
	case N.NetworkTCP:
		return &g.selectedOutboundTCP
	case N.NetworkUDP:
		return &g.selectedOutboundUDP
	default:
		return nil
	}
}

func (g *URLTestGroup) selectedForNetworkLx(network string) adapter.Outbound {
	if slot := g.selectionSlotLx(network); slot != nil {
		return slot.Load()
	}
	return nil
}

func (g *URLTestGroup) setSelectionLx(network string, outbound adapter.Outbound) bool {
	g.selectionWriter.Lock()
	defer g.selectionWriter.Unlock()
	slot := g.selectionSlotLx(network)
	if slot == nil || slot.Load() == outbound {
		return false
	}
	slot.Store(outbound)
	g.noteSelectionChange(network)
	return true
}

func (g *URLTestGroup) setSelectedTCPLx(outbound adapter.Outbound) {
	g.setSelectionLx(N.NetworkTCP, outbound)
}

func (g *URLTestGroup) setSelectedUDPLx(outbound adapter.Outbound) {
	g.setSelectionLx(N.NetworkUDP, outbound)
}

func (g *URLTestGroup) updateSelectedLx(network string, expected, outbound adapter.Outbound, exists bool) (adapter.Outbound, bool) {
	g.selectionWriter.Lock()
	defer g.selectionWriter.Unlock()
	slot := g.selectionSlotLx(network)
	if slot == nil {
		return nil, false
	}
	previous := slot.Load()
	if previous != expected || previous == outbound {
		return previous, false
	}
	if previous != nil && !exists && g.guardAllows(RealTag(previous, network)) {
		return previous, false
	}
	slot.Store(outbound)
	g.noteSelectionChange(network)
	return previous, true
}

// Routing must hand a connection to the group, rather than bypassing its pick.
func (s *URLTest) SelectsPerConnectionLx() {}
