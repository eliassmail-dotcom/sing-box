//go:build with_quic

package finalmask

import (
	"reflect"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
)

func TestLXFinalMaskQUICParamsDefaults(t *testing.T){
	c:=&quic.Config{ChromeParrot:true,MaxIdleTimeout:300*time.Second,KeepAlivePeriod:10*time.Second,MaxIncomingStreams:-1}
	before:=*c
	p,e:=CompileQUICParams(nil,c)
	if e!=nil||p!=nil||!reflect.DeepEqual(before,*c){t.Fatalf("default changed: %v",e)}
	p,e=CompileQUICParams(&option.LXFinalMaskQUICParams{},c)
	if e!=nil||p.bbr||!reflect.DeepEqual(before,*c){t.Fatalf("empty options changed defaults: %v",e)}
}

func TestLXFinalMaskQUICParamsMapping(t *testing.T){
	for _,profile:=range []string{"","conservative","standard","aggressive"}{
		c:=&quic.Config{ChromeParrot:true,MaxIdleTimeout:300*time.Second,KeepAlivePeriod:10*time.Second,MaxIncomingStreams:-1}
		p,e:=CompileQUICParams(&option.LXFinalMaskQUICParams{
			Congestion:"bbr",BBRProfile:profile,DisableChromeParrot:true,
			InitStreamReceiveWindow:65536,MaxStreamReceiveWindow:131072,
			InitConnectionReceiveWindow:262144,MaxConnectionReceiveWindow:524288,
			MaxIdleTimeout:60,KeepAlivePeriod:15,DisablePathMTUDiscovery:true,MaxIncomingStreams:16,
		},c)
		if e!=nil{t.Fatal(e)}
		want:=profile;if want==""{want="standard"}
		if !p.bbr||p.profile.Name()!=want||c.ChromeParrot||!c.DisablePathMTUDiscovery||
			c.InitialStreamReceiveWindow!=65536||c.MaxStreamReceiveWindow!=131072||
			c.InitialConnectionReceiveWindow!=262144||c.MaxConnectionReceiveWindow!=524288||
			c.MaxIdleTimeout!=60*time.Second||c.KeepAlivePeriod!=15*time.Second||c.MaxIncomingStreams!=16{t.Fatalf("wrong mapping: %+v",c)}
	}
}

func TestLXFinalMaskQUICParamsValidation(t *testing.T){
	for _,o:=range []option.LXFinalMaskQUICParams{
		{Congestion:"reno"},
		{BBRProfile:"standard"},
		{Congestion:"bbr",BBRProfile:"unknown"},
		{InitStreamReceiveWindow:16383},
		{MaxConnectionReceiveWindow:17*1024*1024},
		{MaxIdleTimeout:3},
		{MaxIdleTimeout:121},
		{KeepAlivePeriod:1},
		{KeepAlivePeriod:61},
		{MaxIncomingStreams:257},
		{DisableChromeParrot:true,InitStreamReceiveWindow:65536,MaxStreamReceiveWindow:32768},
		{DisableChromeParrot:true,MaxConnectionReceiveWindow:32768},
		{InitStreamReceiveWindow:65536},
	}{
		c:=&quic.Config{ChromeParrot:true}
		before:=*c
		if _,e:=CompileQUICParams(&o,c);e==nil{t.Fatalf("accepted invalid options: %+v",o)}
		if !reflect.DeepEqual(before,*c){t.Fatal("failed compilation mutated config")}
	}
}
