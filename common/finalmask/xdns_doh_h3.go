//go:build with_quic

package finalmask

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/sagernet/sing-box/option"
	"net/http"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	N "github.com/sagernet/sing/common/network"
)

const xdnsDoH3Available=true

func newXDNSDoH3Transport(dialer N.Dialer,cfg *xdnsConfig,tlsConfig *tls.Config)(http.RoundTripper,func()){
	tlsConfig.MinVersion=tls.VersionTLS13
	tlsConfig.NextProtos=[]string{http3.NextProtoH3}
	if tlsConfig.ServerName==""{tlsConfig.ServerName=cfg.resolver.Addr.String()}
	tr:=&http3.Transport{
		TLSClientConfig:tlsConfig,
		DisableCompression:true,
		MaxResponseHeaderBytes:8192,
		QUICConfig:cfg.dohH3Settings.config.Clone(),
		Dial:func(ctx context.Context,_ string,_ *tls.Config,qcfg *quic.Config)(*quic.Conn,error){
			raw,err:=dialer.DialContext(ctx,"udp",cfg.resolver)
			if err!=nil{return nil,err}
			q,err:=quic.DialEarlyConn(ctx,cfg.dohH3Settings.params.WrapCarrier(raw),tlsConfig.Clone(),qcfg)
			if err!=nil{raw.Close();return nil,err}
			cfg.dohH3Settings.params.Apply(q)
			context.AfterFunc(q.Context(),func(){raw.Close()})
			return q,nil
		},
	}
	return tr,func(){_ = tr.Close()}
}

type xdnsH3Settings struct{
	config *quic.Config
	params *QUICParams
}
func compileXDNSH3Params(o *option.LXFinalMaskQUICParams)(*xdnsH3Settings,error){
	c:=&quic.Config{
			HandshakeIdleTimeout:xdnsDoHTimeout,
			MaxIdleTimeout:30*time.Second,
			MaxIncomingStreams:-1,
			DisablePathMTUDiscovery:true,
			InitialStreamReceiveWindow:32*1024,
			MaxStreamReceiveWindow:128*1024,
			InitialConnectionReceiveWindow:128*1024,
			MaxConnectionReceiveWindow:512*1024,
		}
	if o!=nil{
		// Inner resolver QUIC is a small control carrier, not a bulk data
		// transport. Keep the memory envelope smaller than outer QUIC.
		for _,v:=range []uint64{o.InitStreamReceiveWindow,o.MaxStreamReceiveWindow,o.InitConnectionReceiveWindow,o.MaxConnectionReceiveWindow}{
			if v>2*1024*1024{return nil,errors.New("XDNS HTTP/3 receive window exceeds 2 MiB")}
		}
		if o.MaxIncomingStreams!=0{return nil,errors.New("XDNS HTTP/3 does not accept incoming bidirectional streams")}
	}
	p,err:=CompileQUICParams(o,c)
	if err!=nil{return nil,err}
	return &xdnsH3Settings{config:c,params:p},nil
}
