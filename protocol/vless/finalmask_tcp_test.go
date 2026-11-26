package vless

import (
	"testing"
	"encoding/json"

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

func TestLXFinalMaskTCPChainVLESSGuard(t *testing.T){
	var opts option.VLESSOutboundOptions
	if c,err:=prepareTCPChain(opts);c!=nil||err!=nil{t.Fatalf("default changed %v %v",c,err)}
	opts.FinalMaskTCP=[]option.LXFinalMaskTCPMaskOptions{{Type:"fragment",Settings:json.RawMessage(`{"length":2}`)}}
	if c,err:=prepareTCPChain(opts);c==nil||err!=nil{t.Fatalf("plain VLESS rejected %v",err)}
	opts.FinalMaskTCPFragment=&option.LXFinalMaskFragmentOptions{Length:"2"}
	if _,err:=prepareTCPChain(opts);err==nil{t.Fatal("accepted legacy+ordered")}
	opts.FinalMaskTCPFragment=nil
	opts.TLS=&option.OutboundTLSOptions{Enabled:true}
	if _,err:=prepareTCPChain(opts);err==nil{t.Fatal("accepted TLS")}
	opts.TLS=nil
	opts.Transport=&option.V2RayTransportOptions{}
	if _,err:=prepareTCPChain(opts);err==nil{t.Fatal("accepted transport")}
}
