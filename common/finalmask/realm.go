package finalmask

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/realm"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type realmConfig struct{
	controller M.Socksaddr
	url,token,id,serverName string
	stun []netip.AddrPort
}

func compileRealm(raw json.RawMessage)(*realmConfig,error){
	var s struct{
		URL string `json:"url"`
		StunServers []string `json:"stunServers"`
		IPMode string `json:"ipMode"`
		TLS *struct{
			ServerName string `json:"serverName"`
			AllowInsecure bool `json:"allowInsecure"`
		} `json:"tlsConfig"`
		PortMapping *struct{
			Enabled bool `json:"enabled"`
			Timeout int64 `json:"timeout"`
			Lifetime int64 `json:"lifetime"`
		} `json:"portMapping"`
	}
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	u,err:=url.Parse(s.URL)
	if err!=nil||u.Scheme!="realm"||u.User==nil||u.RawQuery!=""||u.Fragment!=""{return nil,errors.New("Realm requires realm://token@IP/id")}
	ip,err:=netip.ParseAddr(u.Hostname())
	if err!=nil||!validXICMPIP(ip){return nil,errors.New("Realm controller requires literal IP")}
	port:=u.Port();if port==""{port="443"}
	v,err:=strconv.ParseUint(port,10,16)
	if err!=nil||v==0{return nil,errors.New("invalid Realm controller port")}
	token,err:=url.PathUnescape(u.User.String())
	if err!=nil||len(token)==0||len(token)>1024||strings.ContainsAny(token,"\r\n"){return nil,errors.New("invalid Realm token")}
	id:=strings.TrimPrefix(u.Path,"/")
	if len(id)==0||len(id)>128||id=="."||id==".."{return nil,errors.New("invalid Realm ID")}
	for _,r:=range id{if !(r>='a'&&r<='z'||r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='-'||r=='_'){return nil,errors.New("Realm ID must be alphanumeric, hyphen or underscore")}}
	if s.PortMapping!=nil&&s.PortMapping.Enabled{return nil,errors.New("Realm port mapping not enabled in pilot")}
	if len(s.StunServers)==0||len(s.StunServers)>4{return nil,errors.New("Realm requires one to four STUN servers")}
	c:=&realmConfig{controller:M.SocksaddrFrom(ip.Unmap(),uint16(v)),token:token,id:id,serverName:u.Hostname()}
	c.url="https://"+net.JoinHostPort(ip.String(),port)
	if s.TLS!=nil{
		if s.TLS.AllowInsecure{return nil,errors.New("Realm requires TLS verification")}
		if s.TLS.ServerName!=""{c.serverName=s.TLS.ServerName}
	}
	mode:=strings.ToLower(s.IPMode)
	if mode!=""&&mode!="dual"&&mode!="v4"&&mode!="v6"{return nil,errors.New("invalid Realm ipMode")}
	var family int
	if mode=="v4"{family=4};if mode=="v6"{family=6}
	seen:=make(map[netip.AddrPort]bool)
	for _,s:=range s.StunServers{
		a,err:=netip.ParseAddrPort(s)
		if err!=nil||!validXICMPIP(a.Addr())||a.Port()==0{return nil,errors.New("Realm STUN requires literal IP:port")}
		a=netip.AddrPortFrom(a.Addr().Unmap(),a.Port())
		f:=6;if a.Addr().Is4(){f=4}
		if family==0{family=f}
		if f!=family||seen[a]{continue}
		seen[a]=true;c.stun=append(c.stun,a)
	}
	if len(c.stun)==0{return nil,errors.New("no Realm STUN server for selected family")}
	return c,nil
}

type realmLimitedTransport struct{rt http.RoundTripper}
type realmLimitedBody struct{io.Reader;io.Closer}
func(t realmLimitedTransport)RoundTrip(r *http.Request)(*http.Response,error){
	resp,err:=t.rt.RoundTrip(r);if err!=nil{return nil,err}
	if resp.ContentLength>16384{resp.Body.Close();return nil,errors.New("Realm response too large")}
	b,err:=io.ReadAll(io.LimitReader(resp.Body,16385));resp.Body.Close()
	if err!=nil{return nil,err}
	if len(b)>16384{return nil,errors.New("Realm response too large")}
	resp.Body=io.NopCloser(strings.NewReader(string(b)))
	return resp,nil
}

func dialRealm(ctx context.Context,dialer N.Dialer,cfg *realmConfig,roots *x509.CertPool)(net.Conn,error){
	ctx,cancel:=context.WithTimeout(ctx,20*time.Second);defer cancel()
	raw,err:=dialer.ListenPacket(ctx,M.SocksaddrFromNetIP(cfg.stun[0]))
	if err!=nil{return nil,err}
	success:=false
	defer func(){if !success{raw.Close()}}()
	stop:=context.AfterFunc(ctx,func(){raw.Close()})
	defer stop()
	if deadline,ok:=ctx.Deadline();ok{if err=raw.SetWriteDeadline(deadline);err!=nil{return nil,err}}
	locals,err:=realm.Discover(ctx,raw,cfg.stun)
	if err!=nil{return nil,err}
	if err=ctx.Err();err!=nil{return nil,err}
	meta,err:=realm.GeneratePunchMetadata()
	if err!=nil{return nil,err}
	tr:=&http.Transport{
		DialContext:func(ctx context.Context,_,_ string)(net.Conn,error){return dialer.DialContext(ctx,"tcp",cfg.controller)},
		TLSClientConfig:&tls.Config{ServerName:cfg.serverName,MinVersion:tls.VersionTLS12,RootCAs:roots},
		ForceAttemptHTTP2:true,DisableCompression:true,MaxConnsPerHost:1,MaxResponseHeaderBytes:8192,
		TLSHandshakeTimeout:5*time.Second,ResponseHeaderTimeout:8*time.Second,
	}
	defer tr.CloseIdleConnections()
	client,err:=realm.NewControlClient(cfg.url,cfg.token,&http.Client{
		Transport:realmLimitedTransport{rt:tr},Timeout:10*time.Second,
		CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse},
	})
	if err!=nil{return nil,err}
	response,err:=client.Connect(ctx,cfg.id,locals,meta)
	if err!=nil{return nil,errors.New("Realm controller connect failed")}
	if response.PunchMetadata!=meta{return nil,errors.New("Realm metadata mismatch")}
	if len(response.Addresses)==0||len(response.Addresses)>4{return nil,errors.New("Realm peer count outside budget")}
	var peers []netip.AddrPort
	seen:=make(map[netip.AddrPort]bool)
	for _,p:=range response.Addresses{
		p=netip.AddrPortFrom(p.Addr().Unmap(),p.Port())
		if !validXICMPIP(p.Addr())||p.Port()==0||p.Addr().Is4()!=cfg.stun[0].Addr().Is4()||seen[p]{continue}
		seen[p]=true;peers=append(peers,p)
	}
	if len(peers)==0{return nil,errors.New("no compatible Realm peers")}
	result,err:=realm.Punch(ctx,raw,peers,meta)
	if err!=nil{return nil,err}
	allowed:=false
	for _,p:=range peers{if p.Addr()==result.PeerAddr.Addr().Unmap(){allowed=true;break}}
	if !allowed{return nil,errors.New("unexpected Realm peer IP")}
	if !stop()||ctx.Err()!=nil{return nil,context.Canceled}
	if err=raw.SetDeadline(time.Time{});err!=nil{return nil,err}
	success=true
	return &realmConn{PacketConn:raw,peer:result.PeerAddr,meta:meta},nil
}

type realmConn struct{
	net.PacketConn
	peer netip.AddrPort
	meta realm.PunchMetadata
}
func(c *realmConn)RemoteAddr()net.Addr{return net.UDPAddrFromAddrPort(c.peer)}
func(c *realmConn)Write(p []byte)(int,error){return c.PacketConn.WriteTo(p,c.RemoteAddr())}
func(c *realmConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	for{
		n,a,err:=c.PacketConn.ReadFrom(p);if err!=nil{return 0,err}
		if M.SocksaddrFromNet(a).Unwrap().AddrPort()!=c.peer{continue}
		if _,err=realm.DecodePunchPacket(p[:n],c.meta);err==nil{continue}
		return n,nil
	}
}
