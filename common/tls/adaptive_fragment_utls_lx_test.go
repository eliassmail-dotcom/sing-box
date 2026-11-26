//go:build with_utls

package tls

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
)

func TestLXAdaptiveFragmentCloneAndWire(t *testing.T) {
	base := lxNewRealityClient(t, "chrome", "", false, false)
	clone := base.Clone().(*RealityClientConfig)
	ctx := adapter.ContextWithAdaptiveRecordFragmentRaceLx(context.Background())
	applyAdaptiveFragmentModeLx(adapter.ContextWithAdaptiveRecordFragmentModeLx(ctx, true), clone)
	if base.uClient.recordFragment || !clone.uClient.recordFragment || base.uClient.config == clone.uClient.config {
		t.Fatal("fragment mode mutated the base config or failed to clone")
	}
	if base.ServerName() != clone.ServerName() || base.keyShare != clone.keyShare || base.shortID != clone.shortID || base.uClient.id.Client != clone.uClient.id.Client || base.uClient.id.Version != clone.uClient.id.Version {
		t.Fatal("fragment mode changed REALITY identity parameters")
	}
	plain := lxRealityFirstFlight(t, base)
	fragmented := lxRealityFirstFlight(t, clone)
	if lxTLSRecordCount(t, plain) != 1 || lxTLSRecordCount(t, fragmented) < 2 {
		t.Fatal("adaptive mode did not change only the TLS record shape")
	}
}
