package dialer

import (
	"context"
	"errors"
	"net"

	"github.com/sagernet/sing-box/common/lxnet"
)

// Only definitive TCP refusals and explicit authenticated-protocol failures
// are penalized by the adaptive path. Preserve the original error chain.
type lxDefinitiveTCPFailure struct{ error }

func (e lxDefinitiveTCPFailure) Unwrap() error                 { return e.error }
func (lxDefinitiveTCPFailure) LXIPRaceDefinitiveFailure() bool { return true }

func shouldRecordIPFailureLx(err error, strict bool) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return false
	}
	if !strict {
		return true
	}
	var definitive interface{ LXIPRaceDefinitiveFailure() bool }
	return errors.As(err, &definitive) && definitive.LXIPRaceDefinitiveFailure()
}

// Each stage is a child of the original attempt context. No timeout is ever
// extended beyond the caller, and cancellation happens after the stage returns.
func dialVerifiedCandidateLx(
	ctx context.Context,
	multi, adaptive bool,
	dial func(context.Context) (net.Conn, error),
	verify func(context.Context, net.Conn) (net.Conn, error),
) (net.Conn, error) {
	attemptCtx := ctx
	stop := func() {}
	if multi {
		budget := lxVerifiedIPAttemptTimeout
		if adaptive {
			budget = lxVerifiedTotalTimeout
		}
		attemptCtx, stop = context.WithTimeout(ctx, budget)
	}
	defer stop()

	tcpCtx := attemptCtx
	stopTCP := func() {}
	if multi && adaptive {
		tcpCtx, stopTCP = context.WithTimeout(attemptCtx, lxVerifiedTCPTimeout)
	}
	raw, err := dial(tcpCtx)
	tcpErr := tcpCtx.Err()
	stopTCP()
	if err != nil || tcpErr != nil || raw == nil {
		if raw != nil {
			_ = raw.Close()
		}
		if tcpErr != nil {
			return nil, tcpErr
		}
		if err == nil {
			return nil, errors.New("tcp_concurrent: dial returned no connection")
		}
		if adaptive && lxnet.IsConnRefused(err) {
			err = lxDefinitiveTCPFailure{err}
		}
		return nil, err
	}

	tlsCtx := attemptCtx
	stopTLS := func() {}
	if multi && adaptive {
		tlsCtx, stopTLS = context.WithTimeout(attemptCtx, lxVerifiedTLSTimeout)
	}
	verified, err := verify(tlsCtx, raw)
	tlsErr := tlsCtx.Err()
	stopTLS()
	if err != nil || tlsErr != nil || verified == nil || attemptCtx.Err() != nil {
		_ = raw.Close()
		if verified != nil {
			_ = verified.Close()
		}
		if tlsErr != nil {
			return nil, tlsErr
		}
		if attemptErr := attemptCtx.Err(); attemptErr != nil {
			return nil, attemptErr
		}
		if err == nil {
			return nil, errors.New("tcp_concurrent: verifier returned nil connection")
		}
		return nil, err
	}
	return verified, nil
}
