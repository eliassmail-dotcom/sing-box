package group

// Smart's Base -> White policy applies to *eligible* nodes, not merely nodes
// with URLTest history. A successful probe can outlive a series of failed
// real connections; in that case a node rejected by LX penalties must not
// keep the Base tier selected forever.
//
// A node is eligible when:
//   - it supports the requested network;
//   - the passive reliability guard has not quarantined its real TCP path;
//   - its classified path-failure penalty is below the rejection threshold.
//
// URLTest history is checked separately when ranking candidates. Cold start
// still prefers Base, but never overrides a known quarantine or rejection.
// Recovery uses the existing proof-of-life logic (successful URLTest/dial)
// and the passive guard's quarantine expiry. No new timers or forced probes.

import (
    "github.com/sagernet/sing-box/adapter"
    N "github.com/sagernet/sing/common/network"
)

func (g *URLTestGroup) priorityNodeEligible(node adapter.Outbound, network string) bool {
    if node == nil || !supportsNetwork(node, network) {
        return false
    }
    tag := RealTag(node, N.NetworkTCP)
    return g.guardAllows(tag) && g.penaltyOf(tag) < penaltyThreshold
}

// Keep the old selection semantics for unrelated URLTest groups. Only Smart
// priority groups reject a previously selected path at the penalty threshold.
func (g *URLTestGroup) selectionNodeEligible(node adapter.Outbound, network string) bool {
    if node == nil {
        return false
    }
    if len(g.priorityOutbounds) > 0 {
        return g.priorityNodeEligible(node, network)
    }
    return g.guardAllows(RealTag(node, network))
}
