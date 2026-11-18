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

const lxVerifiedIPAttemptTimeout = 3 * time.Second

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
    if d.ipRace == nil {
        return nil, errors.New("tcp_concurrent: verified dialing requires opt-in")
    }
    if !destination.IsDomain() {
        return nil, errors.New("tcp_concurrent: verified dialing requires domain address")
    }
    if err := d.initialize(); err != nil {
        return nil, err
    }
    addresses, err := d.lookupLx(ctx, destination.Fqdn)
    if err != nil {
        return nil, err
    }
    if len(addresses) == 0 {
        return nil, errors.New("tcp_concurrent: DNS returned no addresses")
    }
    return d.ipRace.dial(ctx, destination, addresses, addresses[0].Is6(),
        func(raceCtx context.Context, ip netip.Addr) (net.Conn, error) {
            // Do not let a TCP-accepting but REALITY-silent endpoint occupy
            // one of the four slots indefinitely. The outer URLTest/request
            // deadline remains authoritative.
            attemptCtx := raceCtx
            cancel := func() {}
            if len(addresses) > 1 {
                attemptCtx, cancel = context.WithTimeout(raceCtx, lxVerifiedIPAttemptTimeout)
            }
            defer cancel()
            conn, err := d.dialer.DialContext(
                attemptCtx, N.NetworkTCP, M.SocksaddrFrom(ip, destination.Port))
            if err != nil {
                return nil, err
            }
            // The callback is responsible for TLS negotiation; on any
            // handshake error the underlying TCP socket must be closed.
            verified, err := verify(attemptCtx, conn)
            if err != nil {
                _ = conn.Close()
                if verified != nil {
                    _ = verified.Close()
                }
                return nil, err
            }
            if verified == nil {
                _ = conn.Close()
                return nil, errors.New("tcp_concurrent: verifier returned nil connection")
            }
            return verified, nil
        })
}
