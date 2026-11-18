package dialer

// LX experimental IPv4/IPv6 connection racing, adapted from the approach in
// MiChongs/sing-box (common/dialer/concurrent.go, xiaobaf14g-testing) and
// XTLS/Xray-core (transport/internet/happy_eyeballs.go). This intentionally
// keeps the experiment limited to outbound TCP sockets without a detour.
//
// The original VLESS hostname remains owned by the protocol/TLS layer: only
// the socket destination changes to a resolved IP. A short-lived winner
// cache saves a network that blocks most of a host's A records from repeated
// TCP timeouts. Nothing here performs a speculative TLS/REALITY handshake.
import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

const (
	lxIPRaceMaxConcurrent = 4
	lxIPRaceStagger       = 75 * time.Millisecond
	lxIPRaceWinnerTTL     = 10 * time.Minute
	lxIPRaceFailureTTL    = 1 * time.Minute
	lxIPRaceMinHeadStart  = 20 * time.Millisecond
	lxIPRaceMaxHeadStart  = 250 * time.Millisecond
)

// lxIPRace is owned by one outbound's resolve dialer, not shared across
// different VPN endpoints. It is safe for concurrent URLTest/application dials.
type lxIPRace struct {
	mu           sync.Mutex
	winner       netip.Addr
	winnerRTT    time.Duration
	winnerExpiry time.Time
	failed       map[netip.AddrPort]time.Time
}

func newLXIPRace() *lxIPRace {
	return &lxIPRace{failed: make(map[netip.AddrPort]time.Time)}
}

type lxIPRaceResult struct {
	addr    netip.Addr
	conn    net.Conn
	err     error
	latency time.Duration
}

func (r *lxIPRace) ordered(addresses []netip.Addr, port uint16, preferIPv6 bool) ([]netip.Addr, bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if now.After(r.winnerExpiry) {
		r.winner = netip.Addr{}
		r.winnerRTT = 0
	}
	for ip, until := range r.failed {
		if !now.Before(until) {
			delete(r.failed, ip)
		}
	}

	seen := make(map[netip.Addr]bool, len(addresses))
	var preferred, secondary, failing []netip.Addr
	known := false
	for _, ip := range addresses {
		ip = ip.Unmap()
		if !ip.IsValid() || seen[ip] {
			continue
		}
		seen[ip] = true
		switch {
		case ip == r.winner && r.winner.IsValid():
			known = true
		case now.Before(r.failed[netip.AddrPortFrom(ip, port)]):
			failing = append(failing, ip)
		case ip.Is6() == preferIPv6:
			preferred = append(preferred, ip)
		default:
			secondary = append(secondary, ip)
		}
	}

	ordered := make([]netip.Addr, 0, len(seen))
	if known {
		ordered = append(ordered, r.winner)
	}
	for i := 0; i < len(preferred) || i < len(secondary); i++ {
		if i < len(preferred) {
			ordered = append(ordered, preferred[i])
		}
		if i < len(secondary) {
			ordered = append(ordered, secondary[i])
		}
	}
	ordered = append(ordered, failing...)
	delay := lxIPRaceStagger
	if known {
		delay = 2 * r.winnerRTT
		if delay < lxIPRaceMinHeadStart {
			delay = lxIPRaceMinHeadStart
		}
		if delay > lxIPRaceMaxHeadStart {
			delay = lxIPRaceMaxHeadStart
		}
	}
	return ordered, known, delay
}

func (r *lxIPRace) recordWinner(ip netip.Addr, measured time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.winner == ip && r.winnerRTT > 0 {
		measured = r.winnerRTT + (measured-r.winnerRTT)/8
	}
	r.winner = ip
	r.winnerRTT = measured
	r.winnerExpiry = time.Now().Add(lxIPRaceWinnerTTL)
	for key := range r.failed {
		if key.Addr() == ip {
			delete(r.failed, key)
		}
	}
}

func (r *lxIPRace) recordFailure(ip netip.Addr, port uint16) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.winner == ip {
		r.winner = netip.Addr{}
		r.winnerRTT = 0
		r.winnerExpiry = time.Time{}
	}
	if len(r.failed) > 128 {
		clear(r.failed)
	}
	r.failed[netip.AddrPortFrom(ip, port)] = time.Now().Add(lxIPRaceFailureTTL)
}

// dial returns the first successful TCP socket. Failed candidates are
// replaced immediately; otherwise attempts are staggered at 75 ms, with up
// to four live sockets. A completed race cancels and closes every loser.
// Context cancellation and connect_timeout are delegated to the original
// outbound dialer, preserving interface binding and other socket policies.
func (r *lxIPRace) dial(
	ctx context.Context,
	destination M.Socksaddr,
	addresses []netip.Addr,
	preferIPv6 bool,
	dialOne func(context.Context, netip.Addr) (net.Conn, error),
) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ordered, _, delay := r.ordered(addresses, destination.Port, preferIPv6)
	if len(ordered) == 0 {
		return nil, errors.New("tcp_concurrent: DNS returned no usable IP addresses")
	}
	if len(ordered) == 1 {
		return dialOne(ctx, ordered[0])
	}

	raceCtx, cancel := context.WithCancel(ctx)
	results := make(chan lxIPRaceResult, len(ordered))
	var workers sync.WaitGroup
	// A dial may ignore cancellation and finish later. Always drain its
	// buffered result and close the socket rather than leaking a loser.
	defer func() {
		cancel()
		go func() {
			workers.Wait()
			close(results)
		}()
		go func() {
			for result := range results {
				if result.conn != nil {
					_ = result.conn.Close()
				}
			}
		}()
	}()

	next, active := 0, 0
	var failures []error
	start := func() {
		ip := ordered[next]
		next++
		active++
		workers.Add(1)
		go func() {
			defer workers.Done()
			started := time.Now()
			conn, err := dialOne(raceCtx, ip)
			results <- lxIPRaceResult{ip, conn, err, time.Since(started)}
		}()
	}
	start()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	timerC := timer.C
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timerC:
			timerC = nil
			if next < len(ordered) && active < lxIPRaceMaxConcurrent {
				start()
			}
			if next < len(ordered) && active < lxIPRaceMaxConcurrent {
				timer.Reset(lxIPRaceStagger)
				timerC = timer.C
			}
		case outcome := <-results:
			active--
			if outcome.err == nil && outcome.conn != nil {
				if ctx.Err() != nil {
					_ = outcome.conn.Close()
					return nil, ctx.Err()
				}
				r.recordWinner(outcome.addr, outcome.latency)
				return outcome.conn, nil
			}
			if outcome.conn != nil {
				_ = outcome.conn.Close()
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if outcome.err == nil {
				outcome.err = errors.New("tcp_concurrent: dial returned no connection")
			}
			failures = append(failures, outcome.err)
			r.recordFailure(outcome.addr, destination.Port)
			// Do not wait for the timer when an address fails quickly.
			if next < len(ordered) && active < lxIPRaceMaxConcurrent {
				start()
			}
			if active == 0 && next >= len(ordered) {
				return nil, errors.Join(failures...)
			}
			if timerC == nil && next < len(ordered) && active < lxIPRaceMaxConcurrent {
				timer.Reset(lxIPRaceStagger)
				timerC = timer.C
			}
		}
	}
}
