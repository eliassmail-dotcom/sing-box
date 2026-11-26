package vless

import (
	"context"
	"errors"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/urltest"
)

func (h *Outbound) IPWarmupEligible() bool {
	return h.ipWarmupEligible && h.tlsDialer != nil
}

func (h *Outbound) WarmAuthenticatedIP(ctx context.Context) error {
	if !h.IPWarmupEligible() {
		return nil
	}
	// No VLESS payload, multiplex session or URLTest history is created.
	conn, err := h.tlsDialer.DialTLSContext(dialer.ContextWithAuthenticatedIPWarmup(ctx), h.serverAddr)
	if conn != nil {
		_ = conn.Close()
	}
	if errors.Is(err, dialer.ErrAuthenticatedIPWarmupComplete) {
		return nil
	}
	return err
}

func (h *Outbound) BeginIPWarmupProbe() func() {
	if !h.IPWarmupEligible() || !h.ipWarmup.Active() {
		return func() {}
	}
	return h.ipWarmup.BeginProbe(h.Tag())
}

func (h *Outbound) beginIPWarmupUse(ctx context.Context) func() {
	if !h.ipWarmup.Active() || !h.IPWarmupEligible() || urltest.IsIPWarmupURLTest(ctx) {
		return func() {}
	}
	return h.ipWarmup.BeginUse(h.Tag())
}
