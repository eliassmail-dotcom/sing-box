package tls

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
)

func TestLXAdaptiveFragmentConfigGate(t *testing.T) {
	for _, tc := range []struct { name, input string; preparedAllowed bool }{
		{"omitted", "{}", true},
		{"explicit record false", `{"record_fragment":false}`, false},
		{"explicit record true", `{"record_fragment":true}`, false},
		{"explicit fragment", `{"fragment":true}`, false},
		{"explicit fallback delay", `{"fragment_fallback_delay":"50ms"}`, false},
		{"spoof", `{"spoof":"example.org"}`, false},
		{"finalmask", `{"finalmask_fragment":{"packets":"tlshello","length":"100-200","delay":"0"}}`, false},
	} {
		t.Run(tc.name,func(t *testing.T){
			var options option.OutboundTLSOptions
			if err:=json.Unmarshal([]byte(tc.input),&options);err!=nil { t.Fatal(err) }
			if got,want:=adaptiveFragmentConfiguredLx(options),adaptiveFragmentPreparedLx && tc.preparedAllowed;got!=want {
				t.Fatalf("gate=%t want=%t",got,want)
			}
		})
	}
	if adaptiveFragmentContextAllowedLx(context.Background()) != adaptiveFragmentPreparedLx { t.Fatal("incorrect preparation context gate") }
}

func TestLXAdaptiveFragmentWireErrorClassification(t *testing.T) {
	ctx:=adapter.ContextWithAdaptiveRecordFragmentRaceLx(context.Background())
	for _, tc:=range []struct{err error; want bool}{
		{io.EOF,true},{io.ErrUnexpectedEOF,true},{context.DeadlineExceeded,true},{context.Canceled,false},
		{lxRealityVerificationFailure{},false},{errors.New("invalid local config"),false},
	} {
		got:=classifyRealityTransportFailureLx(ctx,tc.err)
		var marker interface{ LXAdaptiveFragmentRetryable() bool }
		if (errors.As(got,&marker) && marker.LXAdaptiveFragmentRetryable())!=tc.want || !errors.Is(got,tc.err) {
			t.Fatalf("classification failed for %v: %v",tc.err,got)
		}
	}
	if got:=classifyRealityTransportFailureLx(context.Background(),io.EOF);got!=io.EOF { t.Fatal("legacy error changed") }
}
