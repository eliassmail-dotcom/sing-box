package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

const (
	lxFragmentModeTTL        = 10 * time.Minute
	lxFragmentModeLimit      = 128
	lxFragmentMinRetryBudget = 300 * time.Millisecond
)

type lxFragmentModeEntry struct {
	fragmented bool
	expiry     time.Time
}

type lxFragmentObservation struct {
	key        netip.AddrPort
	cached     *lxFragmentModeEntry
	used       bool
	invalidate bool
}

func hasMultipleDistinctIPsLx(addresses []netip.Addr) bool {
	var first netip.Addr
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() {
			continue
		}
		if !first.IsValid() {
			first = ip
			continue
		}
		if ip != first {
			return true
		}
	}
	return false
}

func (r *lxIPRace) loadFragmentMode(generation uint64, key netip.AddrPort) *lxFragmentModeEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation != r.generation {
		return nil
	}
	entry := r.fragmentModes[key]
	if entry != nil && !time.Now().Before(entry.expiry) {
		delete(r.fragmentModes, key)
		return nil
	}
	return entry
}

// Caller holds the epoch-checked winner lock.
func (r *lxIPRace) storeFragmentModeLocked(key netip.AddrPort, fragmented bool) {
	if r.fragmentModes == nil {
		r.fragmentModes = make(map[netip.AddrPort]*lxFragmentModeEntry)
	}
	now := time.Now()
	for ip, entry := range r.fragmentModes {
		if !now.Before(entry.expiry) {
			delete(r.fragmentModes, ip)
		}
	}
	if len(r.fragmentModes) >= lxFragmentModeLimit && r.fragmentModes[key] == nil {
		var oldestKey netip.AddrPort
		var oldest time.Time
		for ip, entry := range r.fragmentModes {
			if oldest.IsZero() || entry.expiry.Before(oldest) {
				oldestKey, oldest = ip, entry.expiry
			}
		}
		delete(r.fragmentModes, oldestKey)
	}
	r.fragmentModes[key] = &lxFragmentModeEntry{fragmented: fragmented, expiry: now.Add(lxFragmentModeTTL)}
}

func (r *lxIPRace) invalidateFragmentMode(generation uint64, observed *lxFragmentObservation) {
	if observed == nil || !observed.invalidate || observed.cached == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if generation == r.generation && r.fragmentModes[observed.key] == observed.cached {
		delete(r.fragmentModes, observed.key)
	}
}

func dialAdaptiveFragmentCandidateLx(
	ctx context.Context,
	key netip.AddrPort,
	cached *lxFragmentModeEntry,
	dial func(context.Context) (net.Conn, error),
	verify func(context.Context, net.Conn) (net.Conn, error),
) (net.Conn, error, *lxFragmentObservation) {
	// The original candidate's budget is absolute across both TCP+TLS cycles.
	attemptCtx, cancel := context.WithTimeout(ctx, lxVerifiedTotalTimeout)
	defer cancel()
	fragmented := cached != nil && cached.fragmented
	observed := &lxFragmentObservation{key: key, cached: cached, used: fragmented}
	var firstErr error
	for i := 0; i < 2; i++ {
		var retryable bool
		var verifiedFailure bool
		conn, err := dialVerifiedCandidateLx(attemptCtx, true, true, dial,
			func(tlsCtx context.Context, raw net.Conn) (net.Conn, error) {
				tlsCtx = adapter.ContextWithAdaptiveRecordFragmentRaceLx(tlsCtx)
				tlsCtx = adapter.ContextWithAdaptiveRecordFragmentModeLx(tlsCtx, fragmented)
				verified, err := verify(tlsCtx, raw)
				if err != nil {
					verifiedFailure = true
					var marker interface{ LXAdaptiveFragmentRetryable() bool }
					var definitive interface{ LXIPRaceDefinitiveFailure() bool }
					retryable = errors.As(err, &marker) && marker.LXAdaptiveFragmentRetryable() &&
						!(errors.As(err, &definitive) && definitive.LXIPRaceDefinitiveFailure()) &&
						!errors.Is(err, context.Canceled)
				}
				return verified, err
			})
		if err == nil {
			observed.used = fragmented
			return conn, nil, observed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err(), nil
		}
		// Failure of a retained mode is evidence only for an actual handshake
		// failure or definitive socket refusal, not a canceled/slow TCP dial.
		if verifiedFailure || shouldRecordIPFailureLx(err, true) {
			observed.invalidate = true
		}
		if i == 0 {
			firstErr = err
		}
		deadline, _ := attemptCtx.Deadline()
		if i == 1 || !retryable || attemptCtx.Err() != nil || time.Until(deadline) < lxFragmentMinRetryBudget {
			// Preserve final definitive auth/refusal classification. Do not
			// join a previous timeout with it (F2 deliberately ignores timeouts).
			if i == 1 && !shouldRecordIPFailureLx(err, true) && firstErr != nil {
				err = errors.Join(firstErr, err)
			}
			return nil, err, observed
		}
		// dialVerifiedCandidateLx has closed the first socket before retrying.
		// A cached fragmented mode may fall back to plain, but never loop.
		fragmented = !fragmented
	}
	panic("unreachable adaptive fragment attempt")
}
