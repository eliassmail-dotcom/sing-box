// lx:begin adaptive-warmup
package dialer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/lxnet"
)

// Peer review #10: the F2 verified-budget classification (and F3 fragment
// fallback) keys on refused/reset socket errors. On Windows the net stack
// surfaces Winsock codes (WSAECONNREFUSED), which plain syscall.ECONNREFUSED
// never matches; lxnet.IsConnRefused must classify a REAL refused dial
// correctly on every platform.
func TestRefusedDialClassifiesAsConnRefused(t *testing.T) {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("dial to a closed local port unexpectedly succeeded")
	}
	if err == nil {
		t.Fatal("dial to a closed local port returned no error")
	}
	if !lxnet.IsConnRefused(err) {
		t.Fatalf("refused dial must classify as refused (WSAECONNREFUSED on Windows), got: %v", err)
	}
}

// lx:end adaptive-warmup
