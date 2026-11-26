//go:build with_quic

package finalmask

import (
	"context"
	"crypto/tls"
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
		QUICConfig:&quic.Config{
			HandshakeIdleTimeout:xdnsDoHTimeout,
			MaxIdleTimeout:30*time.Second,
			MaxIncomingStreams:-1,
			DisablePathMTUDiscovery:true,
			InitialStreamReceiveWindow:32*1024,
			MaxStreamReceiveWindow:128*1024,
			InitialConnectionReceiveWindow:128*1024,
			MaxConnectionReceiveWindow:512*1024,
		},
		Dial:func(ctx context.Context,_ string,_ *tls.Config,qcfg *quic.Config)(*quic.Conn,error){
			raw,err:=dialer.DialContext(ctx,"udp",cfg.resolver)
			if err!=nil{return nil,err}
			q,err:=quic.DialEarlyConn(ctx,raw,tlsConfig.Clone(),qcfg)
			if err!=nil{raw.Close();return nil,err}
			context.AfterFunc(q.Context(),func(){raw.Close()})
			return q,nil
		},
	}
	return tr,func(){_ = tr.Close()}
}
