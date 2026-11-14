package group

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func TestLXAdaptiveThresholdKeepsLegacyUntilEnabled(t *testing.T) {
	current := newFailoverNode("current", 0)
	alternative := newFailoverNode("alternative", 0)
	g := newFailoverTestGroup(t, current, alternative)
	g.failover = false
	g.tolerance = 175
	g.setSelectedTCPLx(current)
	g.history.StoreURLTestHistory("current", &adapter.URLTestHistory{Time: time.Now(), Delay: 150})
	g.history.StoreURLTestHistory("alternative", &adapter.URLTestHistory{Time: time.Now(), Delay: 80})
	if got, _ := g.Select(N.NetworkTCP); got != current {
		t.Fatalf("legacy tolerance must keep current, got %v", got)
	}
	g.tolerancePercent = 30
	if got, _ := g.Select(N.NetworkTCP); got != alternative {
		t.Fatalf("30%% adaptive threshold should switch, got %v", got)
	}
	// 20 ms absolute floor: a small variation should not trigger switching.
	g.history.StoreURLTestHistory("current", &adapter.URLTestHistory{Time: time.Now(), Delay: 60})
	g.history.StoreURLTestHistory("alternative", &adapter.URLTestHistory{Time: time.Now(), Delay: 50})
	if got, _ := g.Select(N.NetworkTCP); got != current {
		t.Fatalf("small RTT fluctuations must not trigger switching, got %v", got)
	}
}

func TestLXMinimumHoldAndFailureBypass(t *testing.T) {
	a := newFailoverNode("a", 0)
	b := newFailoverNode("b", 0)
	g := newFailoverTestGroup(t, a, b)
	g.failover = false
	g.tolerance = 175
	g.tolerancePercent = 30
	g.minHold = 30 * time.Second
	g.setSelectedTCPLx(a)
	g.history.StoreURLTestHistory("a", &adapter.URLTestHistory{Time: time.Now(), Delay: 150})
	g.history.StoreURLTestHistory("b", &adapter.URLTestHistory{Time: time.Now(), Delay: 40})
	g.noteSelectionChange(N.NetworkTCP)
	if got, _ := g.Select(N.NetworkTCP); got != a {
		t.Fatalf("healthy node must be held, got %v", got)
	}
	g.lastSwitchTCP.Store(time.Now().Add(-31 * time.Second).UnixNano())
	if got, _ := g.Select(N.NetworkTCP); got != b {
		t.Fatalf("hold expired; expected better node, got %v", got)
	}
	g.noteSelectionChange(N.NetworkTCP)
	g.history.DeleteURLTestHistory("a")
	if got, _ := g.Select(N.NetworkTCP); got != b {
		t.Fatalf("failed node must bypass hold, got %v", got)
	}
}

func TestLXPriorityRecoveryBypassesHold(t *testing.T) {
	base := newFailoverNode("base", 0)
	white := newFailoverNode("white", 0)
	g := newFailoverTestGroup(t, base, white)
	g.failover = false
	g.priorityOutbounds = map[string]bool{"base": true}
	g.minHold = 30 * time.Second
	g.setSelectedTCPLx(white)
	g.noteSelectionChange(N.NetworkTCP)
	g.history.StoreURLTestHistory("white", &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	g.history.StoreURLTestHistory("base", &adapter.URLTestHistory{Time: time.Now(), Delay: 180})
	if got, _ := g.selectPriority(N.NetworkTCP); got != base {
		t.Fatalf("recovered preferred tier must bypass hold, got %v", got)
	}
	g.setSelectedTCPLx(base)
	g.noteSelectionChange(N.NetworkTCP)
	g.history.DeleteURLTestHistory("base")
	if got, _ := g.selectPriority(N.NetworkTCP); got != white {
		t.Fatalf("failed preferred tier must bypass hold, got %v", got)
	}
}

func TestLXURLTestNewOptionsValidation(t *testing.T) {
	cases := []option.URLTestOutboundOptions{
		{TolerancePercent: 101}, {MinHold: badoption.Duration(11 * time.Minute)},
		{Mode: "failover", TolerancePercent: 30}, {Mode: "round_robin", MinHold: badoption.Duration(time.Second)},
		{URL: "https://example.org", URLs: []string{"https://example.net"}},
		{URLs: []string{"https://example.org", "https://example.org"}},
		{URLs: []string{"http://a", "http://b", "http://c", "http://d"}},
		{URLs: []string{"ftp://example.org"}},
	}
	for _, opts := range cases {
		opts.Outbounds = []string{"a"}
		if _, err := NewURLTest(context.Background(), nil, logger.NOP(), "test", opts); err == nil {
			t.Fatalf("expected invalid config: %+v", opts)
		}
	}
	_, err := NewURLTest(context.Background(), nil, logger.NOP(), "test", option.URLTestOutboundOptions{
		Outbounds: []string{"a"}, URLs: []string{"https://example.org", "https://example.net"},
		TolerancePercent: 30, MinHold: badoption.Duration(30 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLXProbeURLsAnySuccessAndCancel(t *testing.T) {
	cancelled := make(chan struct{})
	delay, err := probeURLs(context.Background(), []string{"bad", "good", "slow"}, func(ctx context.Context, link string) (uint16, error) {
		switch link {
		case "bad":
			return 0, errors.New("bad")
		case "good":
			return 72, nil
		default:
			<-ctx.Done()
			close(cancelled)
			return 0, ctx.Err()
		}
	})
	if err != nil || delay != 72 {
		t.Fatalf("expected first successful probe, delay=%d err=%v", delay, err)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("remaining probe was not cancelled")
	}
	if _, err := probeURLs(context.Background(), []string{"bad", "also bad"}, func(context.Context, string) (uint16, error) { return 0, errors.New("failed") }); err == nil {
		t.Fatal("all failed endpoints must mark the node unavailable")
	}
}

func TestLXURLTestTwoEndpointsKeepsAlive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	node := newFailoverNode("only", 0)
	g := newFailoverTestGroup(t, node)
	g.failover = false
	node.addr = server.Listener.Addr().String()
	g.links = []string{server.URL + "/bad", server.URL + "/good"}
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.history.LoadURLTestHistory("only") == nil {
		t.Fatal("node should be healthy after one successful URL")
	}
	g.links = []string{server.URL + "/bad", server.URL + "/bad?x=1"}
	if _, err := g.URLTest(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g.history.LoadURLTestHistory("only") != nil {
		t.Fatal("all failed URLs should remove health history")
	}
}
