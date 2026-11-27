package finalmask

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
)

const xdnsDoHQueue=16
const xdnsDoHTimeout=5*time.Second

type xdnsDoHConn struct{
	ctx context.Context
	cancel context.CancelFunc
	client *http.Client
	transport *http.Transport
	tlsConfig *tls.Config
	closeTransport func()
	cfg *xdnsConfig
	send,receive chan []byte
	start,closeOnce sync.Once
	mu sync.Mutex
	readDeadline,writeDeadline time.Time
	changed chan struct{}
	cooldown time.Time
}

func newXDNSDoHConn(ctx context.Context,dialer N.Dialer,cfg *xdnsConfig)*xdnsDoHConn{
	ctx,cancel:=context.WithCancel(context.WithoutCancel(ctx))
	tlsConfig:=&tls.Config{ServerName:cfg.dohServerName,MinVersion:tls.VersionTLS12,NextProtos:cfg.dohALPN}
	if cfg.dohH3{
		rt,closeRT:=newXDNSDoH3Transport(dialer,cfg,tlsConfig)
		return &xdnsDoHConn{ctx:ctx,cancel:cancel,cfg:cfg,tlsConfig:tlsConfig,closeTransport:closeRT,
			client:&http.Client{Transport:rt,Timeout:xdnsDoHTimeout,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},
			send:make(chan []byte,xdnsDoHQueue),receive:make(chan []byte,xdnsDoHQueue),changed:make(chan struct{})}
	}
	tr:=&http.Transport{
		Proxy:nil,
		DialContext:func(ctx context.Context,network,address string)(net.Conn,error){
			return dialer.DialContext(ctx,"tcp",cfg.resolver)
		},
		TLSClientConfig:tlsConfig,
		ForceAttemptHTTP2:true,
		DisableCompression:true,
		MaxConnsPerHost:cfg.dohWorkers,
		MaxIdleConns:cfg.dohWorkers,
		MaxIdleConnsPerHost:cfg.dohWorkers,
		IdleConnTimeout:30*time.Second,
		TLSHandshakeTimeout:xdnsDoHTimeout,
		ResponseHeaderTimeout:xdnsDoHTimeout,
		MaxResponseHeaderBytes:8192,
	}
	if len(cfg.dohALPN)==1&&cfg.dohALPN[0]=="http/1.1"{
		tr.ForceAttemptHTTP2=false
		tr.TLSNextProto=map[string]func(string,*tls.Conn)http.RoundTripper{}
	}
	return &xdnsDoHConn{ctx:ctx,cancel:cancel,cfg:cfg,transport:tr,tlsConfig:tlsConfig,closeTransport:tr.CloseIdleConnections,
		client:&http.Client{Transport:tr,Timeout:xdnsDoHTimeout,CheckRedirect:func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}},
		send:make(chan []byte,xdnsDoHQueue),receive:make(chan []byte,xdnsDoHQueue),changed:make(chan struct{})}
}
func(c *xdnsDoHConn)ensure(){
	c.start.Do(func(){for i:=0;i<c.cfg.dohWorkers;i++{go c.worker()}})
}
func(c *xdnsDoHConn)worker(){
	for{
		select{
		case <-c.ctx.Done():return
		case p:=<-c.send:
			if c.ctx.Err()!=nil{return}
			c.mu.Lock();blocked:=time.Now().Before(c.cooldown);c.mu.Unlock()
			if blocked{continue}
			b,err:=c.exchange(p)
			if err!=nil{continue}
			select{case <-c.ctx.Done():return;case c.receive<-b:default:}
		}
	}
}
func(c *xdnsDoHConn)exchange(p []byte)([]byte,error){
	req,err:=http.NewRequestWithContext(c.ctx,http.MethodPost,c.cfg.dohURL,bytes.NewReader(p))
	if err!=nil{return nil,err}
	req.Header.Set("Content-Type","application/dns-message")
	req.Header.Set("Accept","application/dns-message")
	req.Header.Set("User-Agent","")
	resp,err:=c.client.Do(req)
	if err!=nil{return nil,err}
	defer resp.Body.Close()
	if resp.StatusCode==http.StatusTooManyRequests{
		c.mu.Lock();c.cooldown=time.Now().Add(5*time.Second);c.mu.Unlock()
	}
	if resp.StatusCode!=http.StatusOK{return nil,errors.New("XDNS DoH response status")}
	typ,_,err:=mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err!=nil||typ!="application/dns-message"{return nil,errors.New("invalid XDNS DoH response content type")}
	b,err:=io.ReadAll(io.LimitReader(resp.Body,4097))
	if err!=nil{return nil,err}
	if len(b)<12||len(b)>4096{return nil,errors.New("invalid XDNS DoH response size")}
	return b,nil
}
func(c *xdnsDoHConn)Close()error{
	c.closeOnce.Do(func(){c.cancel();c.closeTransport()})
	return nil
}
func(c *xdnsDoHConn)LocalAddr()net.Addr{return &net.UDPAddr{IP:net.IPv4zero}}
func(c *xdnsDoHConn)RemoteAddr()net.Addr{return &net.UDPAddr{IP:net.IP(c.cfg.resolver.Addr.AsSlice()),Port:int(c.cfg.resolver.Port)}}
func(c *xdnsDoHConn)deadline(read bool)(time.Time,<-chan struct{}){
	c.mu.Lock();defer c.mu.Unlock()
	if read{return c.readDeadline,c.changed}
	return c.writeDeadline,c.changed
}
func(c *xdnsDoHConn)setDeadline(t time.Time,read,write bool)error{
	c.mu.Lock();defer c.mu.Unlock()
	if read{c.readDeadline=t};if write{c.writeDeadline=t}
	close(c.changed);c.changed=make(chan struct{})
	return nil
}
func(c *xdnsDoHConn)SetDeadline(t time.Time)error{return c.setDeadline(t,true,true)}
func(c *xdnsDoHConn)SetReadDeadline(t time.Time)error{return c.setDeadline(t,true,false)}
func(c *xdnsDoHConn)SetWriteDeadline(t time.Time)error{return c.setDeadline(t,false,true)}
func dohTimer(deadline time.Time)(*time.Timer,<-chan time.Time,error){
	if deadline.IsZero(){return nil,nil,nil}
	if !time.Now().Before(deadline){return nil,nil,os.ErrDeadlineExceeded}
	t:=time.NewTimer(time.Until(deadline));return t,t.C,nil
}
func(c *xdnsDoHConn)Write(p []byte)(int,error){
	if len(p)<12||len(p)>4096{return 0,errors.New("invalid XDNS DoH query size")}
	c.ensure()
	b:=bytes.Clone(p)
	for{
		if c.ctx.Err()!=nil{return 0,net.ErrClosed}
		d,changed:=c.deadline(false)
		timer,timeout,err:=dohTimer(d);if err!=nil{return 0,err}
		select{
		case <-c.ctx.Done():if timer!=nil{timer.Stop()};return 0,net.ErrClosed
		case c.send<-b:if timer!=nil{timer.Stop()};return len(p),nil
		case <-changed:
		case <-timeout:
		}
		if timer!=nil{timer.Stop()}
	}
}
func(c *xdnsDoHConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.ensure()
	for{
		if c.ctx.Err()!=nil{return 0,net.ErrClosed}
		d,changed:=c.deadline(true)
		timer,timeout,err:=dohTimer(d);if err!=nil{return 0,err}
		select{
		case <-c.ctx.Done():if timer!=nil{timer.Stop()};return 0,net.ErrClosed
		case b:=<-c.receive:if timer!=nil{timer.Stop()};return copy(p,b),nil
		case <-changed:
		case <-timeout:
		}
		if timer!=nil{timer.Stop()}
	}
}
