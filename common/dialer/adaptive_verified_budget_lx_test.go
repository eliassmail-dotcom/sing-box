package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func TestLXAdaptiveVerifiedRaceReachesAllNine(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	var reached atomic.Int32
	conn, err := r.dialAtGeneration(ctx, M.Socksaddr{Fqdn: "nine.example.test", Port: 443},
		addresses, false, r.currentGeneration(), true,
		func(ctx context.Context, _ netip.Addr) (net.Conn, error) {
			reached.Add(1)
			return dialVerifiedCandidateLx(ctx, true, true, func(tcpCtx context.Context) (net.Conn, error) {
				<-tcpCtx.Done()
				return nil, tcpCtx.Err()
			}, func(context.Context, net.Conn) (net.Conn, error) {
				t.Error("verify called after failed TCP")
				return nil, errors.New("unexpected verify")
			})
		})
	if conn != nil || err == nil || reached.Load() != 9 {
		t.Fatalf("expected all nine failed TCP attempts, got %d, conn=%v err=%v", reached.Load(), conn, err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.failed) != 0 {
		t.Fatalf("timeouts polluted failure cache: %v", r.failed)
	}
}

func TestLXAdaptiveVerifiedSeparateStageBudgetAndLiveStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, peer := net.Pipe()
	defer peer.Close()
	conn, err := dialVerifiedCandidateLx(ctx, true, true,
		func(ctx context.Context) (net.Conn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(600 * time.Millisecond):
				return client, nil
			}
		},
		func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(600 * time.Millisecond):
				return raw, nil
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() { _, _ = peer.Write([]byte{42}) }()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err != nil || b[0] != 42 {
		t.Fatalf("returned stream unusable: %v, byte=%d", err, b[0])
	}
}

func TestLXAdaptiveVerifiedParentDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := dialVerifiedCandidateLx(ctx, true, true, func(ctx context.Context) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}, func(context.Context, net.Conn) (net.Conn, error) {
		t.Fatal("verify after TCP timeout")
		return nil, nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || shouldRecordIPFailureLx(err, true) {
		t.Fatalf("expected unpenalized parent timeout: %v", err)
	}
}

func TestLXAdaptiveVerifiedFailureClassification(t *testing.T) {
	for _, tc := range []struct{ err error; want bool }{
		{context.Canceled, false}, {context.DeadlineExceeded, false},
		{errors.New("transport EOF"), false}, {syscall.ECONNREFUSED, false},
		{lxDefinitiveTCPFailure{syscall.ECONNREFUSED}, true},
	} {
		if got := shouldRecordIPFailureLx(tc.err, true); got != tc.want {
			t.Errorf("%v: got %v want %v", tc.err, got, tc.want)
		}
	}
}

func TestLXAdaptiveVerifiedOldGenerationCannotWrite(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()[:2]
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	old := r.currentGeneration()
	go func() {
		conn, err := r.dialAtGeneration(context.Background(),
			M.Socksaddr{Fqdn: "old.example.test", Port: 443}, addresses, false, old, true,
			func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
				if ip != addresses[0] {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				close(started)
				<-release
				c, p := net.Pipe()
				_ = p.Close()
				return c, nil
			})
		if conn != nil { _ = conn.Close() }
		done <- err
	}()
	<-started
	r.resetHistory()
	r.recordFailure(old, addresses[1], 443)
	close(release)
	select {
	case err := <-done:
		if err != nil { t.Fatal(err) }
	case <-time.After(time.Second):
		t.Fatal("old race did not finish")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.winner.IsValid() || len(r.failed) != 0 || r.generation == old {
		t.Fatalf("stale history repopulated: %v %v generation=%d", r.winner, r.failed, r.generation)
	}
}
