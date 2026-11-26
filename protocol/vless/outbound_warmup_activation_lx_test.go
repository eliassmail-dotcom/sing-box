//go:build with_utls

// lx:begin adaptive-warmup
package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

// Peer review #10: F1/F3 must actually ACTIVATE on Windows (and every supported
// OS), not merely compile. The standard VLESS construction path is the gate:
// a direct REALITY outbound with tcp_concurrent and a domain server becomes
// warmup-eligible only when the IPWarmupCoordinator is in the context — the
// same wiring box.New enables via urltest.IPWarmupSupportedOS().

type warmupNetworkManager struct{ adapter.NetworkManager }

func (m *warmupNetworkManager) DefaultOptions() adapter.NetworkOptions {
	return adapter.NetworkOptions{}
}

func (m *warmupNetworkManager) DefaultOptionsPtr() *adapter.NetworkOptions { return nil }

func (m *warmupNetworkManager) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

func (m *warmupNetworkManager) AutoDetectInterface() bool { return false }

func (m *warmupNetworkManager) ProtectFunc() control.Func { return nil }

func (m *warmupNetworkManager) AutoDetectInterfaceFunc() control.Func { return nil }

func (m *warmupNetworkManager) AutoRedirectOutputMarkFunc() control.Func { return nil }

func (m *warmupNetworkManager) AutoRedirectOutputMark() uint32 { return 0 }

type warmupTransportManager struct{ adapter.DNSTransportManager }

func (m *warmupTransportManager) Transports() []adapter.DNSTransport { return nil }
func (m *warmupTransportManager) Transport(string) (adapter.DNSTransport, bool) {
	return nil, false
}
func (m *warmupTransportManager) Default() adapter.DNSTransport { return nil }

func newWarmupTestContext() context.Context {
	ctx := context.Background()
	ctx = service.ContextWith[adapter.DNSTransportManager](ctx, &warmupTransportManager{})
	ctx = service.ContextWith[adapter.NetworkManager](ctx, &warmupNetworkManager{})
	return ctx
}

func newAdaptiveWarmupOptions(t *testing.T) option.VLESSOutboundOptions {
	t.Helper()
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	return option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "warmup.example.com",
			ServerPort: 443,
		},
		UUID: "6e8a7f36-0c02-4f4a-9b39-0d73a37ba8a7",
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled: true,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: "chrome",
				},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: publicKey,
					ShortID:   "0123456789abcdef",
				},
			},
		},
		DialerOptions: option.DialerOptions{
			AbstractDialerOptions: option.AbstractDialerOptions{
				TCPConcurrent: true,
			},
		},
	}
}

func TestVLESSAdaptiveWarmupActivatesWithCoordinator(t *testing.T) {
	ctx := service.ContextWithPtr(newWarmupTestContext(), urltest.NewIPWarmupCoordinator(context.Background()))
	outbound, err := NewOutbound(ctx, nil, log.NewNOPFactory().Logger(), "warm", newAdaptiveWarmupOptions(t))
	require.NoError(t, err)
	v := outbound.(*Outbound)
	require.NotNil(t, v.ipWarmup, "coordinator must be picked up from the context")
	require.True(t, v.IPWarmupEligible(), "F1 eligibility + F3 adaptive dialer must activate with the coordinator present")
	// Peer review #11: F1 eligibility alone does not prove F3. Assert the
	// actual adaptive dial path: the standard construction must wrap the TLS
	// dialer in the adaptive REALITY dialer with record fragmentation armed.
	adaptive, ok := v.tlsDialer.(interface{ AdaptiveRecordFragmentEnabledLx() bool })
	require.True(t, ok, "tlsDialer must be the adaptive REALITY dialer")
	require.True(t, adaptive.AdaptiveRecordFragmentEnabledLx(), "F3 adaptive record fragmentation must be armed")
}

func TestVLESSAdaptiveWarmupInactiveWithoutCoordinator(t *testing.T) {
	// Control: the exact same options without a coordinator stay on the
	// ordinary (non-adaptive) path — iOS behavior before b40, any OS with the
	// coordinator absent.
	outbound, err := NewOutbound(newWarmupTestContext(), nil, log.NewNOPFactory().Logger(), "plain", newAdaptiveWarmupOptions(t))
	require.NoError(t, err)
	v := outbound.(*Outbound)
	require.Nil(t, v.ipWarmup)
	require.False(t, v.IPWarmupEligible())
	adaptive, ok := v.tlsDialer.(interface{ AdaptiveRecordFragmentEnabledLx() bool })
	require.True(t, ok)
	require.False(t, adaptive.AdaptiveRecordFragmentEnabledLx(), "without the coordinator the plain dialer must stay unarmed")
}

// lx:end adaptive-warmup
