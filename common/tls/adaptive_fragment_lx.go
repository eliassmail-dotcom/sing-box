package tls

import (
	"context"
	"errors"
	"io"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/lxnet"
	"github.com/sagernet/sing-box/common/lxsniffguard"
	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

// Unprepared b39 has a bool record_fragment and cannot distinguish omitted
// from explicit false. prepare-b38 patches these two gates once LX35 and
// FinalMask are present. Fail closed in every other build.
const adaptiveFragmentPreparedLx = true

func adaptiveFragmentConfiguredLx(options option.OutboundTLSOptions) bool {
	return !options.Fragment && options.RecordFragment == nil && options.FinalMaskFragment == nil && options.FragmentFallbackDelay == 0 && options.Spoof == "" && options.SpoofMethod == ""
}

func adaptiveFragmentContextAllowedLx(ctx context.Context) bool {
	return lxsniffguard.AttemptFromContext(ctx) == nil
}

// The caller is the native, direct, iOS VLESS construction path. The
// capability test also excludes non-REALITY and wrapped TLS configurations.
func NewAdaptiveRealityDialerLx(dialer N.Dialer, config Config, options option.OutboundTLSOptions) Dialer {
	_, capable := config.(interface{ setAdaptiveRecordFragmentLx() })
	return &defaultDialer{
		dialer: dialer, config: config,
		adaptiveRecordFragment: capable && adaptiveFragmentConfiguredLx(options),
	}
}

// NewAdaptiveRealityDialerLx must be the ONLY producer of an armed dialer.
//
// AdaptiveRecordFragmentEnabledLx reports whether this dialer was built by
// NewAdaptiveRealityDialerLx with record fragmentation armed, as opposed to the
// plain NewDialer result. The flag itself is unexported; this probe is the
// verification surface for the F3 activation test through the standard VLESS
// construction path (peer review #11).
func (d *defaultDialer) AdaptiveRecordFragmentEnabledLx() bool {
	return d.adaptiveRecordFragment
}

func applyAdaptiveFragmentModeLx(ctx context.Context, config Config) {
	if adapter.AdaptiveRecordFragmentRaceLx(ctx) && adapter.AdaptiveRecordFragmentModeLx(ctx) {
		if reality, ok := config.(interface{ setAdaptiveRecordFragmentLx() }); ok {
			reality.setAdaptiveRecordFragmentLx()
		}
	}
}

// Only the actual wire handshake may produce this marker, never configuration
// or ClientHello construction. Preserve the underlying error and its text.
type lxRealityTransportFailure struct{ error }

func (e lxRealityTransportFailure) Unwrap() error                   { return e.error }
func (lxRealityTransportFailure) LXAdaptiveFragmentRetryable() bool { return true }

func classifyRealityTransportFailureLx(ctx context.Context, err error) error {
	if !adapter.AdaptiveRecordFragmentRaceLx(ctx) || err == nil ||
		errors.Is(err, context.Canceled) {
		return err
	}
	var definitive interface{ LXIPRaceDefinitiveFailure() bool }
	if errors.As(err, &definitive) && definitive.LXIPRaceDefinitiveFailure() {
		return err
	}
	var timeout net.Error
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		lxnet.IsConnReset(err) || errors.Is(err, context.DeadlineExceeded) ||
		(errors.As(err, &timeout) && timeout.Timeout()) {
		return lxRealityTransportFailure{err}
	}
	return err
}
