//go:build with_quic

package finalmask

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/option"
	bbr "github.com/sagernet/sing-quic/congestion_meta2"
	brutal "github.com/sagernet/sing-quic/hysteria/congestion"
	"github.com/sagernet/quic-go/congestion"
	"github.com/sagernet/quic-go/monotime"
)

type QUICParams struct{
	profile bbr.Profile
	bbr bool
	brutalUp uint64
	disableLossCompensation bool
}

// CompileQUICParams applies only explicit settings to the caller's defaults.
// Chrome's pinned transport parameters cannot be overridden silently.
func CompileQUICParams(o *option.LXFinalMaskQUICParams,c *quic.Config)(*QUICParams,error){
	if o==nil{return nil,nil}
	p:=&QUICParams{}
	switch strings.ToLower(o.Congestion){
	case "", "reno":
		if o.BBRProfile!=""{return nil,errors.New("bbrProfile requires congestion=bbr")}
	case "bbr":
		p.bbr=true
		profile:=strings.ToLower(o.BBRProfile)
		if profile==""{profile="standard"}
		var err error
		p.profile,err=bbr.ParseProfile(profile);if err!=nil{return nil,err}
	case "force-brutal":
		if o.BBRProfile!=""{return nil,errors.New("bbrProfile requires congestion=bbr")}
		var err error
		p.brutalUp,err=parseBrutalBandwidth(o.BrutalUp)
		if err!=nil{return nil,err}
		if p.brutalUp<65536{return nil,errors.New("force-brutal requires brutalUp of at least 65536 bytes/s")}
		p.disableLossCompensation=o.BrutalDisableLossCompensation
	case "brutal":
		return nil,errors.New("negotiated brutal requires Hysteria2 authentication; use explicit force-brutal for QUIC/XHTTP")
	default:return nil,errors.New("unsupported QUIC congestion")
	}
	if o.BrutalDown!=""{return nil,errors.New("brutalDown requires server-side or negotiated Hysteria2 support")}
	if p.brutalUp==0&&(o.BrutalUp!=""||o.BrutalDisableLossCompensation){return nil,errors.New("Brutal options require force-brutal")}
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
	if p==nil{return}
	if p.bbr{c.SetCongestionControl(bbr.NewBbrSenderWithProfile(c.InitialPacketSize(),p.profile));return}
	if p.brutalUp!=0{c.SetCongestionControl(p.newBrutalSender(c.InitialPacketSize()))}
}

// Xray interprets these units as bits/s with binary multipliers.
// Cap explicit client speed at 128 MiB/s to bound mobile pacing budgets.
func parseBrutalBandwidth(s string)(uint64,error){
	s=strings.ToLower(strings.TrimSpace(s))
	if s==""{return 0,nil}
	i:=0
	for i<len(s)&&(s[i]>='0'&&s[i]<='9'||s[i]=='.'){i++}
	v,err:=strconv.ParseFloat(s[:i],64)
	if err!=nil{return 0,errors.New("invalid brutal bandwidth")}
	var mul float64
	switch strings.TrimSpace(s[i:]){
	case "","b","bps":mul=1
	case "k","kb","kbps":mul=1024
	case "m","mb","mbps":mul=1024*1024
	case "g","gb","gbps":mul=1024*1024*1024
	case "t","tb","tbps":mul=1024*1024*1024*1024
	default:return 0,errors.New("unsupported brutal bandwidth unit")
	}
	bits:=v*mul
	if bits<0||bits>float64(128*1024*1024*8){return 0,errors.New("brutal bandwidth exceeds mobile limit")}
	return uint64(bits)/8,nil
}

// With loss compensation disabled the existing sender retains its initial
// ACK rate of one. All other pacing and QUIC callbacks are unchanged.
type uncompensatedBrutal struct{*brutal.BrutalSender}
func(*uncompensatedBrutal)OnCongestionEventEx(congestion.ByteCount,monotime.Time,[]congestion.AckedPacketInfo,[]congestion.LostPacketInfo){}
var _ congestion.CongestionControlEx=(*uncompensatedBrutal)(nil)

func(p *QUICParams)newBrutalSender(size congestion.ByteCount)congestion.CongestionControlEx{
	s:=brutal.NewBrutalSender(p.brutalUp,size,false,nil)
	if p.disableLossCompensation{return &uncompensatedBrutal{s}}
	return s
}
