package dialer

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

type fragmentRetryTestError struct{ error }

func (e fragmentRetryTestError) Unwrap() error                   { return e.error }
func (fragmentRetryTestError) LXAdaptiveFragmentRetryable() bool { return true }

type fragmentAuthTestError struct{}

func (fragmentAuthTestError) Error() string                   { return "reality verification failed" }
func (fragmentAuthTestError) LXIPRaceDefinitiveFailure() bool { return true }

func TestLXAdaptiveFragmentCandidateModes(t *testing.T) {
	key := netip.MustParseAddrPort("192.0.2.1:443")
	for _, tc := range []struct {
		name                string
		cached              *lxFragmentModeEntry
		firstErr            error
		tcpErr              error
		wantDials           int
		wantFirst, wantLast bool
		wantSuccess         bool
	}{
		{name: "plain success", wantDials: 1, wantSuccess: true},
		{name: "plain transport retry", firstErr: fragmentRetryTestError{io.EOF}, wantDials: 2, wantLast: true, wantSuccess: true},
		{name: "cached fragment success", cached: &lxFragmentModeEntry{fragmented: true}, wantDials: 1, wantFirst: true, wantLast: true, wantSuccess: true},
		{name: "cached fragment falls back to plain", cached: &lxFragmentModeEntry{fragmented: true}, firstErr: fragmentRetryTestError{io.EOF}, wantDials: 2, wantFirst: true, wantSuccess: true},
		{name: "auth reject", firstErr: fragmentAuthTestError{}, wantDials: 1},
		{name: "local config error", firstErr: errors.New("bad key share"), wantDials: 1},
		{name: "TCP fail", tcpErr: io.EOF, wantDials: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var dials, handshakes int
			var modes []bool
			var previous *warmupTrackedConn
			conn, err, observed := dialAdaptiveFragmentCandidateLx(ctx, key, tc.cached,
				func(context.Context) (net.Conn, error) {
					dials++
					if previous != nil {
						select {
						case <-previous.closed:
						default:
							t.Fatal("first socket still open at retry")
						}
					}
					if tc.tcpErr != nil {
						return nil, tc.tcpErr
					}
					raw, peer := net.Pipe()
					t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
					previous = &warmupTrackedConn{Conn: raw, closed: make(chan struct{})}
					return previous, nil
				},
				func(ctx context.Context, raw net.Conn) (net.Conn, error) {
					handshakes++
					if !adapter.AdaptiveRecordFragmentRaceLx(ctx) {
						t.Fatal("missing verification marker")
					}
					modes = append(modes, adapter.AdaptiveRecordFragmentModeLx(ctx))
					if handshakes == 1 && tc.firstErr != nil {
						return nil, tc.firstErr
					}
					return raw, nil
				})
			if conn != nil {
				defer conn.Close()
			}
			if dials != tc.wantDials || (err == nil) != tc.wantSuccess || (conn != nil) != tc.wantSuccess {
				t.Fatalf("dials=%d conn=%v err=%v", dials, conn, err)
			}
			if tc.tcpErr == nil && (len(modes) != tc.wantDials || modes[0] != tc.wantFirst || modes[len(modes)-1] != tc.wantLast) {
				t.Fatalf("unexpected modes %v", modes)
			}
			if tc.wantSuccess && (observed == nil || observed.used != tc.wantLast) {
				t.Fatal("successful mode not reported")
			}
			if _, auth := tc.firstErr.(fragmentAuthTestError); auth && !shouldRecordIPFailureLx(err, true) {
				t.Fatal("auth rejection classification lost")
			}
		})
	}
}

func TestLXAdaptiveFragmentSharedDeadline(t *testing.T) {
	key := netip.MustParseAddrPort("192.0.2.1:443")
	ctx, cancel := context.WithTimeout(context.Background(), 450*time.Millisecond)
	defer cancel()
	var dials int
	conn, err, _ := dialAdaptiveFragmentCandidateLx(ctx, key, nil,
		func(context.Context) (net.Conn, error) {
			dials++
			raw, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
			return raw, nil
		},
		func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			if !adapter.AdaptiveRecordFragmentModeLx(ctx) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(220 * time.Millisecond):
					return nil, fragmentRetryTestError{io.EOF}
				}
			}
			t.Error("retry started with insufficient remaining budget")
			return nil, io.EOF
		})
	if conn != nil || err == nil || dials != 1 {
		t.Fatalf("unexpected result: dials=%d conn=%v err=%v", dials, conn, err)
	}
}

func TestLXAdaptiveFragmentRetryCannotExtendCandidateBudget(t *testing.T) {
	key := netip.MustParseAddrPort("192.0.2.1:443")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	var dials int
	conn, err, _ := dialAdaptiveFragmentCandidateLx(ctx, key, nil,
		func(ctx context.Context) (net.Conn, error) {
			dials++
			deadline, _ := ctx.Deadline()
			if deadline.After(parentDeadline) {
				t.Error("TCP escaped caller deadline")
			}
			raw, peer := net.Pipe()
			t.Cleanup(func() { _ = peer.Close(); _ = raw.Close() })
			return raw, nil
		},
		func(ctx context.Context, raw net.Conn) (net.Conn, error) {
			deadline, _ := ctx.Deadline()
			if deadline.After(parentDeadline) {
				t.Error("TLS escaped caller deadline")
			}
			if !adapter.AdaptiveRecordFragmentModeLx(ctx) {
				return nil, fragmentRetryTestError{io.EOF}
			}
			<-ctx.Done()
			return nil, fragmentRetryTestError{ctx.Err()}
		})
	if conn != nil || err == nil || dials != 2 {
		t.Fatalf("unexpected result: dials=%d conn=%v err=%v", dials, conn, err)
	}
}

func TestLXAdaptiveFragmentCacheEpochTTLAndCAS(t *testing.T) {
	r := newLXIPRace()
	key := netip.MustParseAddrPort("192.0.2.1:443")
	otherPort := netip.MustParseAddrPort("192.0.2.1:8443")
	epoch := r.currentGeneration()
	record := func(epoch uint64, mode bool) {
		r.recordRaceWinnerWithFragment(epoch, key.Addr(), time.Millisecond, true, &lxFragmentObservation{key: key, used: mode})
	}
	record(epoch, true)
	first := r.loadFragmentMode(epoch, key)
	if first == nil || !first.fragmented || r.loadFragmentMode(epoch, otherPort) != nil {
		t.Fatal("bad cache key/mode")
	}
	record(epoch, false)
	newer := r.loadFragmentMode(epoch, key)
	r.invalidateFragmentMode(epoch, &lxFragmentObservation{key: key, cached: first, invalidate: true})
	if newer == nil || newer.fragmented || r.loadFragmentMode(epoch, key) != newer {
		t.Fatal("old failure erased newer authenticated mode")
	}
	r.invalidateFragmentMode(epoch, &lxFragmentObservation{key: key, cached: newer, invalidate: true})
	if r.loadFragmentMode(epoch, key) != nil {
		t.Fatal("failed mode not invalidated")
	}
	record(epoch, true)
	r.mu.Lock()
	r.fragmentModes[key] = &lxFragmentModeEntry{fragmented: true, expiry: time.Now().Add(-time.Second)}
	r.mu.Unlock()
	if r.loadFragmentMode(epoch, key) != nil {
		t.Fatal("expired mode reused")
	}
	record(epoch, true)
	r.resetHistory()
	record(epoch, true)
	if r.loadFragmentMode(r.currentGeneration(), key) != nil {
		t.Fatal("old epoch repopulated cache")
	}
}

func TestLXAdaptiveFragmentOnlyConsumedWinnerWritesMode(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()[:2]
	firstKey := netip.AddrPortFrom(addresses[0], 443)
	secondKey := netip.AddrPortFrom(addresses[1], 443)
	epoch := r.currentGeneration()
	ctx, cancel := context.WithTimeout(ContextWithAuthenticatedIPWarmup(context.Background()), 2*time.Second)
	defer cancel()
	var completed atomic.Int32
	secondStarted := make(chan struct{})
	conn, err := r.dialAtGenerationWithFragment(ctx, M.Socksaddr{Fqdn: "fragment.example.test", Port: 443}, addresses, false, epoch, true,
		func(ctx context.Context, ip netip.Addr) (net.Conn, error, *lxFragmentObservation) {
			if ip == addresses[0] {
				<-secondStarted
			} else {
				close(secondStarted)
				<-ctx.Done()
			}
			raw, peer := net.Pipe()
			_ = peer.Close()
			completed.Add(1)
			return raw, nil, &lxFragmentObservation{key: netip.AddrPortFrom(ip, 443), used: true}
		})
	if conn != nil || !errors.Is(err, ErrAuthenticatedIPWarmupComplete) || completed.Load() != 2 {
		t.Fatalf("unexpected result: %v %v", conn, err)
	}
	if r.loadFragmentMode(epoch, firstKey) == nil || r.loadFragmentMode(epoch, secondKey) != nil {
		t.Fatal("late loser wrote mode")
	}
}
