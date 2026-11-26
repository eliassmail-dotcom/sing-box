//go:build !windows

// lx:begin adaptive-warmup
package lxnet

import (
	"errors"
	"syscall"
)

// Socket-error classification for the lx adaptive paths. On Unix-likes (and
// iOS/Darwin) syscall.ECONNREFUSED/ECONNRESET are the real socket errnos, so
// the plain errors.Is check is exact. See errno_windows.go for the Windows
// WSAECONNREFUSED/WSAECONNRESET caveat.

// IsConnRefused reports whether err is a TCP "connection refused" socket error.
func IsConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// IsConnReset reports whether err is a "connection reset" socket error.
func IsConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

// lx:end adaptive-warmup
