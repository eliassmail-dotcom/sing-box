//go:build windows

// lx:begin adaptive-warmup
package lxnet

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Socket-error classification for the lx adaptive paths (peer review #10).
//
// On Windows the net stack surfaces Winsock codes: a refused TCP dial is
// WSAECONNREFUSED (10061) and a reset connection is WSAECONNRESET (10054).
// The syscall package's ECONNREFUSED/ECONNRESET are synthetic APPLICATION_ERROR
// constants there, so errors.Is(err, syscall.ECONNREFUSED) silently NEVER
// matches a real dial error on Windows. Both are checked.

// IsConnRefused reports whether err is a TCP "connection refused" socket error.
func IsConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, windows.WSAECONNREFUSED)
}

// IsConnReset reports whether err is a "connection reset" socket error.
func IsConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, windows.WSAECONNRESET)
}

// IsTruncatedDatagramRead reports the Winsock error returned by a UDP read
// when the datagram exceeds the receive buffer. The excess is discarded by
// Winsock; callers must discard the entire datagram, not decode its prefix.
func IsTruncatedDatagramRead(err error) bool {
	return errors.Is(err, windows.WSAEMSGSIZE)
}

// lx:end adaptive-warmup
