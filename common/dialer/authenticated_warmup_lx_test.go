package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type warmupTrackedConn struct {
	net.Conn
	closed chan struct{}
	once sync.Once
}

func (c *warmupTrackedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestLXAuthenticatedWarmupClosesWinnerAndDrainsLoser(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()[:2]
	ctx, cancel := context.WithTimeout(ContextWithAuthenticatedIPWarmup(context.Background()), 2*time.Second)
	defer cancel()
	loserStarted := make(chan struct{})
	loserCancelled := make(chan struct{})
	releaseLoser := make(chan struct{})
	var once sync.Once
	defer once.Do(func(){ close(releaseLoser) })
	makeConn := func() *warmupTrackedConn {
		raw, peer := net.Pipe()
		t.Cleanup(func(){ _ = peer.Close(); _ = raw.Close() })
		return &warmupTrackedConn{Conn: raw, closed: make(chan struct{})}
	}
	winner, loser := makeConn(), makeConn()
	done := make(chan error, 1)
	go func() {
		conn, err := r.dialAtGeneration(ctx, M.Socksaddr{Fqdn: "warm.example.test", Port: 443}, addresses, false, r.currentGeneration(), true,
			func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
				if ip == addresses[0] {
					<-loserStarted
					return winner, nil
				}
				close(loserStarted)
				<-ctx.Done()
				close(loserCancelled)
				<-releaseLoser
				return loser, nil
			})
		if conn != nil { _ = conn.Close(); done <- errors.New("warmup returned a stream"); return }
		done <- err
	}()
	select { case <-winner.closed: case <-time.After(time.Second): t.Fatal("winner not closed immediately") }
	select { case <-loserCancelled: case <-time.After(time.Second): t.Fatal("loser not cancelled") }
	select { case <-done: t.Fatal("slot returned before late loser cleanup"); default: }
	once.Do(func(){ close(releaseLoser) })
	select {
	case err := <-done:
		if !errors.Is(err, ErrAuthenticatedIPWarmupComplete) { t.Fatal(err) }
	case <-time.After(time.Second): t.Fatal("race did not drain")
	}
	select { case <-loser.closed: default: t.Fatal("late loser leaked") }
	if r.needsAuthenticatedWarmup(r.currentGeneration(), addresses) { t.Fatal("authenticated winner not retained") }
}

func TestLXAuthenticatedWarmupRequiresCurrentDNSAndProof(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()
	epoch := r.currentGeneration()
	if r.needsAuthenticatedWarmup(epoch, []netip.Addr{addresses[0], addresses[0]}) {
		t.Fatal("single distinct IP must not warm")
	}
	r.recordWinner(epoch, addresses[0], time.Millisecond)
	if !r.needsAuthenticatedWarmup(epoch, addresses) { t.Fatal("TCP-only winner treated as verified") }
	r.recordRaceWinner(epoch, addresses[0], time.Millisecond, true)
	if r.needsAuthenticatedWarmup(epoch, addresses) { t.Fatal("fresh authenticated winner re-probed") }
	if !r.needsAuthenticatedWarmup(epoch, addresses[1:]) { t.Fatal("stale DNS winner accepted") }
	r.resetHistory()
	if r.needsAuthenticatedWarmup(epoch, addresses) { t.Fatal("old generation allowed to start") }
	if !r.needsAuthenticatedWarmup(r.currentGeneration(), addresses) { t.Fatal("new generation did not require proof") }
}
