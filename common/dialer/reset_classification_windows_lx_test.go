//go:build windows

// lx:begin adaptive-warmup
package dialer

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/sagernet/sing-box/common/lxnet"
)

// Peer review #11: direct WSAECONNRESET check — the refused-dial test covers
// only WSAECONNREFUSED. A real connection reset (server closes with
// SO_LINGER=0 → RST) must classify via lxnet.IsConnReset; plain
// syscall.ECONNRESET never matches it on Windows (errno 10054 is
// WSAECONNRESET, verified live).
func TestResetDialClassifiesAsConnReset(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverClosed := make(chan struct{})
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			close(serverClosed)
			return
		}
		// SO_LINGER{On, 0} makes Close send an RST instead of a FIN.
		raw, _ := conn.(*net.TCPConn).SyscallConn()
		raw.Control(func(fd uintptr) {
			_ = syscall.SetsockoptLinger(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
		})
		_ = conn.Close()
		close(serverClosed)
	}()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-serverClosed
	// Give the RST a moment to arrive, then force the error surfaces.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, werr := conn.Write([]byte("lx")); werr != nil {
			lastErr = werr
			break
		}
		if _, rerr := conn.Read(make([]byte, 16)); rerr != nil {
			lastErr = rerr
			break
		}
		_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
		time.Sleep(50 * time.Millisecond)
	}
	if lastErr == nil {
		t.Fatal("connection reset by RST close was not observed")
	}
	if !lxnet.IsConnReset(lastErr) {
		t.Fatalf("reset connection must classify as conn reset (WSAECONNRESET on Windows), got: %v", lastErr)
	}
	if lxnet.IsConnRefused(lastErr) {
		t.Fatalf("a reset connection must not classify as refused, got: %v", lastErr)
	}
}

// lx:end adaptive-warmup
