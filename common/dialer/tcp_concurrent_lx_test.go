package dialer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

func lxRaceTestAddresses() []netip.Addr {
	return []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
		netip.MustParseAddr("192.0.2.4"),
		netip.MustParseAddr("192.0.2.5"),
		netip.MustParseAddr("192.0.2.6"),
		netip.MustParseAddr("192.0.2.7"),
		netip.MustParseAddr("192.0.2.8"),
		netip.MustParseAddr("192.0.2.9"),
	}
}

func TestLXIPRaceSixthIPv4WinsAndIsRemembered(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()
	target := addresses[5]
	destination := M.Socksaddr{Fqdn: "uk.example.test", Port: 443}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var attempts []netip.Addr
	dial := func(ctx context.Context, ip netip.Addr) (net.Conn, error) {
		mu.Lock()
		attempts = append(attempts, ip)
		mu.Unlock()
		if ip != target {
			return nil, errors.New("blackholed endpoint")
		}
		client, server := net.Pipe()
		t.Cleanup(func() { _ = server.Close() })
		return client, nil
	}

	conn, err := r.dial(ctx, destination, addresses, false, dial)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()

	r.mu.Lock()
	remembered := r.winner
	r.mu.Unlock()
	if remembered != target {
		t.Fatalf("winner = %s, want sixth IPv4 %s", remembered, target)
	}

	mu.Lock()
	attempts = nil
	mu.Unlock()
	second, err := r.dial(ctx, destination, addresses, false, dial)
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	mu.Lock()
	firstAttempt := attempts[0]
	mu.Unlock()
	if firstAttempt != target {
		t.Fatalf("cached winner not tried first: got %s", firstAttempt)
	}
}

func TestLXIPRaceAllIPsFail(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()[:3]
	sentinel := errors.New("unreachable")
	destination := M.Socksaddr{Fqdn: "failed.example.test", Port: 443}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := r.dial(ctx, destination, addresses, false,
		func(context.Context, netip.Addr) (net.Conn, error) {
			return nil, sentinel
		})
	if conn != nil || !errors.Is(err, sentinel) {
		t.Fatalf("expected joined error, got conn=%v err=%v", conn, err)
	}
}

func TestLXIPRaceHonorsCallerCancellation(t *testing.T) {
	r := newLXIPRace()
	destination := M.Socksaddr{Fqdn: "cancel.example.test", Port: 443}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	conn, err := r.dial(ctx, destination, lxRaceTestAddresses(), false,
		func(ctx context.Context, _ netip.Addr) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
	if conn != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got conn=%v err=%v", conn, err)
	}
}

func TestLXIPRaceDoesNotTryIPOutsideCurrentDNSAnswer(t *testing.T) {
	r := newLXIPRace()
	addresses := lxRaceTestAddresses()
	r.recordWinner(addresses[5], 20*time.Millisecond)
	resolved := []netip.Addr{addresses[0], addresses[1]}
	ordered, hasWinner, _ := r.ordered(resolved, 443, false)
	if hasWinner || len(ordered) != 2 || ordered[0] != addresses[0] || ordered[1] != addresses[1] {
		t.Fatalf("race must stay within the current DNS answer, got %v; history=%t", ordered, hasWinner)
	}
}

func TestLXIPRaceOptionDecodesAsBool(t *testing.T) {
	var options option.DialerOptions
	if err := json.Unmarshal([]byte(`{"tcp_concurrent":true,"connect_timeout":"2s"}`), &options); err != nil {
		t.Fatal(err)
	}
	if !options.TCPConcurrent {
		t.Fatal("tcp_concurrent not propagated into outbound dialer options")
	}
	var ordinary option.DialerOptions
	if ordinary.TCPConcurrent {
		t.Fatal("legacy configs must remain sequential/dual-stack by default")
	}
}

func TestLXIPRaceResetOnNetworkChange(t *testing.T) {
	r := newLXIPRace()
	target := netip.MustParseAddr("192.0.2.6")
	r.recordWinner(target, 22*time.Millisecond)
	r.recordFailure(netip.MustParseAddr("192.0.2.4"), 443)
	r.resetHistory()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.winner.IsValid() || r.winnerRTT != 0 || !r.winnerExpiry.IsZero() || len(r.failed) != 0 {
		t.Fatalf("outbound IP preference survived interface update: winner=%v failures=%v", r.winner, r.failed)
	}
}

func TestLXIPRaceDoesNotRememberTCPOnlySuccess(t *testing.T) {
    // The first address accepts TCP, but an actual handshake verifier would
    // reject its decoy response. Only the second authenticated address wins.
    r := newLXIPRace()
    addresses := []netip.Addr{
        netip.MustParseAddr("192.0.2.11"),
        netip.MustParseAddr("192.0.2.12"),
    }
    destination := M.Socksaddr{Fqdn:"uk.example.test", Port:443}
    ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
    defer cancel()
    var sockets []net.Conn
    var mu sync.Mutex
    dialAndVerify := func(ctx context.Context, ip netip.Addr) (net.Conn,error) {
        client, server := net.Pipe()
        mu.Lock()
        sockets = append(sockets, server)
        mu.Unlock()
        if ip == addresses[0] {
            _ = client.Close()
            return nil, errors.New("REALITY decoy failed certificate verification")
        }
        return client, nil
    }
    conn,err := r.dial(ctx,destination,addresses,false,dialAndVerify)
    if err != nil {t.Fatal(err)}
    _ = conn.Close()
    mu.Lock()
    defer mu.Unlock()
    for _, socket := range sockets { _=socket.Close() }
    r.mu.Lock()
    winner:=r.winner
    failures:=len(r.failed)
    r.mu.Unlock()
    if winner != addresses[1] || failures == 0 {
        t.Fatalf("expected second verified IP, winner=%v failures=%d", winner, failures)
    }
}
