package dialer

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

type authenticatedIPWarmupKey struct{}

// A background warmup intentionally returns no stream, even on success.
var ErrAuthenticatedIPWarmupComplete = errors.New("authenticated IP warmup complete or unnecessary")

func ContextWithAuthenticatedIPWarmup(ctx context.Context) context.Context {
	return context.WithValue(ctx, authenticatedIPWarmupKey{}, true)
}

func isAuthenticatedIPWarmup(ctx context.Context) bool {
	ok, _ := ctx.Value(authenticatedIPWarmupKey{}).(bool)
	return ok
}

func (r *lxIPRace) needsAuthenticatedWarmup(generation uint64, addresses []netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation {
		return false
	}
	seen := make(map[netip.Addr]bool, len(addresses))
	for _, ip := range addresses {
		ip = ip.Unmap()
		if ip.IsValid() {
			seen[ip] = true
		}
	}
	if len(seen) < 2 {
		return false
	}
	return !r.winnerAuthenticated || !seen[r.winner] || !time.Now().Before(r.winnerExpiry)
}
