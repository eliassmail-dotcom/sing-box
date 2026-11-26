package vless

import (
	"testing"

	"github.com/sagernet/sing-box/option"
)

func TestLXFinalMaskTCPVLESSGuard(t *testing.T) {
	var opts option.VLESSOutboundOptions
	if m, err := prepareTCPFragment(opts); m != nil || err != nil { t.Fatalf("default changed: %v %v",m,err) }
	opts.FinalMaskTCPFragment = &option.LXFinalMaskFragmentOptions{Packets:"1-3",Length:"8"}
	if m,err:=prepareTCPFragment(opts); m==nil||err!=nil{t.Fatalf("plain VLESS rejected: %v",err)}
	opts.Flow="xtls-rprx-vision"
	if _,err:=prepareTCPFragment(opts);err==nil{t.Fatal("accepted flow")}
	opts.Flow=""
	opts.Transport=&option.V2RayTransportOptions{}
	if _,err:=prepareTCPFragment(opts);err==nil{t.Fatal("accepted transport")}
	opts.Transport=nil
	opts.TLS=&option.OutboundTLSOptions{Enabled:true}
	if _,err:=prepareTCPFragment(opts);err==nil{t.Fatal("accepted TLS")}
}
