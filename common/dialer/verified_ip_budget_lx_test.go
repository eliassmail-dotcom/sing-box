package dialer

import (
    "context"
    "net"
    "net/netip"
    "sync/atomic"
    "testing"
    "time"

    M "github.com/sagernet/sing/common/metadata"
)

// With all first five A records dropping packets, a 2s URLTest must still
// have enough time to try IP #6. This is the real UK-home-Wi-Fi failure mode.
// A 3s per-IP timeout with a four-slot limit did not reach #6 in time.
func TestLXVerifiedIPRaceReachesSixthAfterFiveBlackholes(t *testing.T) {
    addresses := lxRaceTestAddresses()
    target := addresses[5]
    r := newLXIPRace()
    ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
    defer cancel()

    var active, peak atomic.Int32
    raceStart := time.Now()
    conn, err := r.dial(ctx,
        M.Socksaddr{Fqdn: "uk.example.test", Port: 443},
        addresses, false,
        func(candidateCtx context.Context, ip netip.Addr) (net.Conn, error) {
            count := active.Add(1)
            for {
                top := peak.Load()
                if top >= count || peak.CompareAndSwap(top, count) {break}
            }
            defer active.Add(-1)
            if ip == target {
                client, server := net.Pipe()
                go func(){<-candidateCtx.Done();_ = server.Close()}()
                return client, nil
            }
            // Simulate silent TCP blackhole or REALITY ServerHello timeout.
            attemptCtx, stop := context.WithTimeout(candidateCtx, lxVerifiedIPAttemptTimeout)
            defer stop()
            <-attemptCtx.Done()
            return nil, attemptCtx.Err()
        })
    if err != nil { t.Fatalf("sixth IP not reached in 2s: %v",err) }
    _ = conn.Close()
    if elapsed := time.Since(raceStart); elapsed >= 2*time.Second {
        t.Fatalf("sixth IP reached after URLTest deadline: %v",elapsed)
    }
    if got := peak.Load(); got > int32(lxIPRaceMaxConcurrent) {
        t.Fatalf("too many concurrent handshakes: %d > %d",got,lxIPRaceMaxConcurrent)
    }
    r.mu.Lock()
    winner := r.winner
    r.mu.Unlock()
    if winner != target {
        t.Fatalf("cached winner = %s, expected sixth IP %s",winner,target)
    }
}
