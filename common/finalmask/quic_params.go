//go:build with_quic

package finalmask

import (
	"errors"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	bbr "github.com/sagernet/sing-quic/congestion_meta2"
)

type QUICParams struct{
	profile bbr.Profile
	bbr bool
}

// CompileQUICParams applies only explicit settings to the caller's defaults.
// Chrome's pinned transport parameters cannot be overridden silently.
func CompileQUICParams(o *option.LXFinalMaskQUICParams,c *quic.Config)(*QUICParams,error){
	if o==nil{return nil,nil}
	p:=&QUICParams{}
	switch strings.ToLower(o.Congestion){
	case "":
		if o.BBRProfile!=""{return nil,errors.New("bbrProfile requires congestion=bbr")}
	case "bbr":
		p.bbr=true
		profile:=strings.ToLower(o.BBRProfile)
		if profile==""{profile="standard"}
		var err error
		p.profile,err=bbr.ParseProfile(profile);if err!=nil{return nil,err}
	default:return nil,errors.New("unsupported QUIC congestion; only explicit bbr supported")
	}
	windows:=[]uint64{o.InitStreamReceiveWindow,o.MaxStreamReceiveWindow,o.InitConnectionReceiveWindow,o.MaxConnectionReceiveWindow}
	for _,v:=range windows{
		if v!=0&&(v<16384||v>16*1024*1024){return nil,errors.New("QUIC receive window must be 16 KiB to 16 MiB")}
	}
	if o.MaxIdleTimeout!=0&&(o.MaxIdleTimeout<4||o.MaxIdleTimeout>120){return nil,errors.New("QUIC maxIdleTimeout must be 4-120 seconds")}
	if o.KeepAlivePeriod!=0&&(o.KeepAlivePeriod<2||o.KeepAlivePeriod>60){return nil,errors.New("QUIC keepAlivePeriod must be 2-60 seconds")}
	if o.MaxIncomingStreams!=0&&(o.MaxIncomingStreams<8||o.MaxIncomingStreams>256){return nil,errors.New("QUIC maxIncomingStreams must be 8-256")}
	next:=*c
	if o.DisableChromeParrot{next.ChromeParrot=false}
	if next.ChromeParrot&&(windows[0]!=0||windows[1]!=0||windows[2]!=0||windows[3]!=0||o.MaxIdleTimeout!=0||o.MaxIncomingStreams!=0){
		return nil,errors.New("QUIC receive windows, idle timeout and stream limit require disableChromeParrot")
	}
	if o.InitStreamReceiveWindow!=0{next.InitialStreamReceiveWindow=o.InitStreamReceiveWindow}
	if o.MaxStreamReceiveWindow!=0{next.MaxStreamReceiveWindow=o.MaxStreamReceiveWindow}
	if o.InitConnectionReceiveWindow!=0{next.InitialConnectionReceiveWindow=o.InitConnectionReceiveWindow}
	if o.MaxConnectionReceiveWindow!=0{next.MaxConnectionReceiveWindow=o.MaxConnectionReceiveWindow}
	// Account for quic-go defaults when validating a partial override.
	check:=func(a,b,defaultA,defaultB uint64)bool{
		if a==0{a=defaultA};if b==0{b=defaultB};return a<=b
	}
	if !check(next.InitialStreamReceiveWindow,next.MaxStreamReceiveWindow,512*1024,6*1024*1024)||
		!check(next.InitialConnectionReceiveWindow,next.MaxConnectionReceiveWindow,512*1024,15*1024*1024){
		return nil,errors.New("QUIC initial receive window exceeds maximum")
	}
	if o.MaxIdleTimeout!=0{next.MaxIdleTimeout=time.Duration(o.MaxIdleTimeout)*time.Second}
	if o.KeepAlivePeriod!=0{next.KeepAlivePeriod=time.Duration(o.KeepAlivePeriod)*time.Second}
	if o.DisablePathMTUDiscovery{next.DisablePathMTUDiscovery=true}
	if o.MaxIncomingStreams!=0{next.MaxIncomingStreams=o.MaxIncomingStreams}
	*c=next
	return p,nil
}

func(p *QUICParams)Apply(c *quic.Conn){
	if p!=nil&&p.bbr{c.SetCongestionControl(bbr.NewBbrSenderWithProfile(c.InitialPacketSize(),p.profile))}
}
