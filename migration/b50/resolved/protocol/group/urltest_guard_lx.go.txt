package group

// LX passive reliability guard. This is deliberately opt-in and observes
// application-stream symptoms, NOT TLS ClientHello or wire packet counts.
// No read deadline is injected: normal idle HTTP/2, streaming and SSO must
// remain untouched. A stall by itself is too ambiguous to quarantine a node.

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	lxGuardWindow     = 45 * time.Second
	lxGuardQuarantine = 60 * time.Second
	lxGuardMinBytes   = 12 * 1024
	lxGuardMaxBytes   = 32 * 1024
)

type lxGuardNode struct {
	hardFailures map[string]time.Time
	streamStalls map[string]time.Time
	suspectUntil time.Time
	blockedUntil time.Time
	pending      chan struct{} // one in-flight group dial when node is suspect
}

type lxPassiveGuard struct {
	mu    sync.Mutex
	nodes map[string]*lxGuardNode
	now   func() time.Time // injected clock in tests
}

func newLXPassiveGuard() *lxPassiveGuard {
	return &lxPassiveGuard{nodes: make(map[string]*lxGuardNode), now: time.Now}
}

func (g *lxPassiveGuard) node(tag string) *lxGuardNode {
	n := g.nodes[tag]
	if n == nil {
		n = &lxGuardNode{pending: make(chan struct{}, 1)}
		g.nodes[tag] = n
	}
	return n
}

func lxRecent(events map[string]time.Time, cutoff time.Time) map[string]time.Time {
	for target, at := range events {
		if at.Before(cutoff) {
			delete(events, target)
		}
	}
	return events
}

// Only independent target destinations count as independent evidence. Three
// failures to one blocked website must NOT quarantine a healthy VPN node.
// The caller must supply a stable target identity (Socksaddr.String).
func (g *lxPassiveGuard) record(tag string, hard bool, target string) bool {
	if tag == "" || target == "" {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	n := g.node(tag)
	n.hardFailures = lxRecent(n.hardFailures, now.Add(-lxGuardWindow))
	n.streamStalls = lxRecent(n.streamStalls, now.Add(-lxGuardWindow))
	if hard {
		if n.hardFailures == nil {
			n.hardFailures = make(map[string]time.Time)
		}
		n.hardFailures[target] = now
	} else {
		if n.streamStalls == nil {
			n.streamStalls = make(map[string]time.Time)
		}
		n.streamStalls[target] = now
	}
	n.suspectUntil = now.Add(lxGuardWindow)
	if now.Before(n.blockedUntil) {
		return false
	}
	if len(n.hardFailures) < 3 {
		if len(n.hardFailures) == 0 || len(n.streamStalls) < 2 {
			return false
		}
		// Two stalled destinations and one hard-failing destination must
		// identify THREE distinct targets; double-reporting one website
		// is not independent evidence of a bad VPN path.
		unique := make(map[string]struct{}, len(n.hardFailures)+len(n.streamStalls))
		for target := range n.streamStalls {
			unique[target] = struct{}{}
		}
		for target := range n.hardFailures {
			unique[target] = struct{}{}
		}
		if len(unique) < 3 {
			return false
		}
	}
	n.blockedUntil = now.Add(lxGuardQuarantine)
	n.hardFailures = nil
	n.streamStalls = nil
	return true
}

func (g *lxPassiveGuard) blocked(tag string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	n := g.nodes[tag]
	return n != nil && g.now().Before(n.blockedUntil)
}

// A successful proxy dial proves that a connection could be established, not
// that a larger payload can flow. Keep passive stalls until their window expires.
func (g *lxPassiveGuard) success(tag string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if n := g.nodes[tag]; n != nil {
		n.hardFailures = nil
		n.suspectUntil = time.Time{}
	}
}

// enter limits parallel group-level proxy dial attempts ONLY for suspect nodes.
// Different application streams cannot safely share one net.Conn, so this is
// not TLS Singleflight; it only bounds pressure after a real failure.
func (g *lxPassiveGuard) enter(ctx context.Context, tag string) (func(), error) {
	if g == nil {
		return func() {}, nil
	}
	g.mu.Lock()
	n := g.node(tag)
	suspect := g.now().Before(n.suspectUntil)
	pending := n.pending
	g.mu.Unlock()
	if !suspect {
		return func() {}, nil
	}
	select {
	case pending <- struct{}{}:
		return func() { <-pending }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func lxSuspiciousStreamRead(err error, sent, received uint64) bool {
	if err == nil || errors.Is(err, context.Canceled) || sent == 0 ||
		received < lxGuardMinBytes || received > lxGuardMaxBytes {
		return false
	}
	var netErr net.Error
	return errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}

type lxObservedConn struct {
	net.Conn
	sent     atomic.Uint64
	received atomic.Uint64
	reported atomic.Bool
	onStall  func()
}

func (c *lxObservedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.sent.Add(uint64(n))
	}
	return n, err
}

func (c *lxObservedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.received.Add(uint64(n))
	}
	if lxSuspiciousStreamRead(err, c.sent.Load(), c.received.Load()) && c.reported.CompareAndSwap(false, true) {
		c.onStall()
	}
	return n, err
}

// guardedConn never changes transport deadlines, return values or error types.
// Its report is only a weak hint; record() needs independent confirmation.
func (g *URLTestGroup) guardedConn(tag string, target string, conn net.Conn) net.Conn {
	if g.passiveGuard == nil || conn == nil {
		return conn
	}
	return &lxObservedConn{Conn: conn, onStall: func() {
		if g.passiveGuard.record(tag, false, target) {
			g.guardQuarantined(tag)
		}
	}}
}

func (g *URLTestGroup) guardQuarantined(tag string) {
	g.logger.Warn("lx reliability: repeated path failures, temporary quarantine for ", tag)
	g.history.DeleteURLTestHistory(tag)
	// Deliberately use SPEC 054's moveSelection (no Interrupt), never the
	// regular URLTest update path, to preserve existing YouTube/HTTP streams.
	for _, network := range []string{"tcp", "udp"} {
		tcp, udp := g.selectedLx()
		current := tcp
		if network == "udp" {
			current = udp
		}
		if current == nil || RealTag(current, network) != tag {
			continue
		}
		next, _ := g.selectForUpdate(network, false)
		if next != nil && next != current {
			g.moveSelection(network, next)
		}
	}
	g.history.NotifyUpdated()
}

func (g *URLTestGroup) guardAllows(nodeTag string) bool {
	return g.passiveGuard == nil || !g.passiveGuard.blocked(nodeTag)
}

func (g *URLTestGroup) guardDial(ctx context.Context, tag string, target string, siteOnOpen bool, dial func() (net.Conn, error)) (net.Conn, error) {
	if g.passiveGuard == nil {
		return dial()
	}
	release, err := g.passiveGuard.enter(ctx, tag)
	if err != nil {
		return nil, err
	}
	defer release()
	conn, err := dial()
	if err == nil {
		g.passiveGuard.success(tag)
	} else if isPathDeadDialError(err, siteOnOpen) && !errors.Is(ctx.Err(), context.Canceled) {
		if g.passiveGuard.record(tag, true, target) {
			g.guardQuarantined(tag)
		}
	}
	return conn, err
}
