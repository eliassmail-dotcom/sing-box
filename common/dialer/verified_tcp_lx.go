package dialer

// The optional verified-TCP race keeps DNS resolution and network-interface
// binding in the existing LX resolve dialer while moving the "winner" point
// from TCP connect to the caller's completed TLS/REALITY handshake.
//
// There is deliberately no dependency on common/tls here: protocol-specific
// handshakes are supplied by the caller as a callback. Neither the original
// hostname nor TLS SNI/REALITY keys are rewritten.
import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Keep the legacy verified-race budget for other protocols. Native direct
// VLESS REALITY opts in to independent stage budgets during construction.
const lxVerifiedIPAttemptTimeout = time.Second

const (
	lxVerifiedTCPTimeout = time.Second
	lxVerifiedTLSTimeout = 1500 * time.Millisecond
	lxVerifiedTotalTimeout = lxVerifiedTCPTimeout + lxVerifiedTLSTimeout
)

// EnableAdaptiveVerifiedTCP is called only during outbound construction,
// before the resolve dialer can be used concurrently.
func (d *resolveDialer) EnableAdaptiveVerifiedTCP() {
	d.adaptiveVerifiedTCP = d.ipRace != nil
}

// IPRaceEnabled is false for every non-opt-in resolve dialer, preserving the
// ordinary sing-box TLS and ECH call path.
func (d *resolveDialer) IPRaceEnabled() bool {
	return d.ipRace != nil
}

// DialVerifiedTCP supplies a fully verified stream or tries another resolved
// candidate. A candidate is successful ONLY if verify returns (conn,nil),
// allowing the TLS package to enforce normal X.509 or REALITY authentication.
// The caller closes the returned connection after the VLESS session ends.
// The callback may receive different connections concurrently and MUST use a
// fresh handshake configuration for each candidate.
func (d *resolveDialer) DialVerifiedTCP(
	ctx context.Context,
	destination M.Socksaddr,
	verify func(context.Context, net.Conn) (net.Conn, error),
) (net.Conn, error) {
	return d.dialVerifiedTCP(ctx, destination, verify, false)
}

// A separate optional capability confines F3 to this dial. In particular,
// DNS lookups do not inherit an adaptive-fragment policy for other endpoints.
func (d *resolveDialer) DialVerifiedTCPAdaptiveFragmentLx(
	ctx context.Context,
	destination M.Socksaddr,
	verify func(context.Context, net.Conn) (net.Conn, error),
) (net.Conn, error) {
	return d.dialVerifiedTCP(ctx, destination, verify, true)
}

func (d *resolveDialer) dialVerifiedTCP(
	ctx context.Context,
	destination M.Socksaddr,
	verify func(context.Context, net.Conn) (net.Conn, error),
	fragmentRequested bool,
) (net.Conn, error) {
	if d.ipRace == nil {
		return nil, errors.New("tcp_concurrent: verified dialing requires opt-in")
	}
	if !destination.IsDomain() {
		return nil, errors.New("tcp_concurrent: verified dialing requires domain address")
	}
	if err := d.initialize(); err != nil {
		return nil, err
	}
	generation := d.ipRace.currentGeneration()
	addresses, err := d.lookupLx(ctx, destination.Fqdn)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, errors.New("tcp_concurrent: DNS returned no addresses")
	}
	if isAuthenticatedIPWarmup(ctx) && (!d.adaptiveVerifiedTCP || !d.ipRace.needsAuthenticatedWarmup(generation, addresses)) {
		return nil, ErrAuthenticatedIPWarmupComplete
	}
	multi := hasMultipleDistinctIPsLx(addresses)
	fragmentEnabled := multi && d.adaptiveVerifiedTCP && fragmentRequested
	return d.ipRace.dialAtGenerationWithFragment(ctx, destination, addresses, addresses[0].Is6(), generation, d.adaptiveVerifiedTCP,
		func(raceCtx context.Context, ip netip.Addr) (net.Conn, error, *lxFragmentObservation) {
			dial := func(tcpCtx context.Context) (net.Conn, error) {
				return d.dialer.DialContext(tcpCtx, N.NetworkTCP, M.SocksaddrFrom(ip, destination.Port))
			}
			if !fragmentEnabled {
				conn, err := dialVerifiedCandidateLx(raceCtx, len(addresses) > 1, d.adaptiveVerifiedTCP, dial, verify)
				return conn, err, nil
			}
			key := netip.AddrPortFrom(ip.Unmap(), destination.Port)
			cached := d.ipRace.loadFragmentMode(generation, key)
			return dialAdaptiveFragmentCandidateLx(raceCtx, key, cached, dial, verify)
		})
}
