package finalmask

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestLXFinalMaskXDNSDoHExchange(t *testing.T){
	payload:=bytes.Repeat([]byte{7},32)
	s:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.Method!="POST"||r.Header.Get("Content-Type")!="application/dns-message"||r.Header.Get("Accept")!="application/dns-message"{w.WriteHeader(400);return}
		b,err:=io.ReadAll(r.Body);if err!=nil||!bytes.Equal(b,payload){w.WriteHeader(400);return}
		w.Header().Set("Content-Type","application/dns-message")
		w.Write(b)
	}))
	defer s.Close()
	cfg,err:=compileXDNS(json.RawMessage(strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353",s.URL+"/dns-query",1)))
	if err!=nil{t.Fatal(err)}
	if cfg.network!="https"||cfg.dohWorkers!=4{t.Fatal("bad config")}
	ctx,cancel:=context.WithCancel(context.Background())
	c:=newXDNSDoHConn(ctx,N.SystemDialer,cfg)
	defer c.Close()
	cancel()
	roots:=x509.NewCertPool();roots.AddCert(s.Certificate())
	c.transport.TLSClientConfig.RootCAs=roots
	c.SetDeadline(time.Now().Add(2*time.Second))
	if n,err:=c.Write(payload);err!=nil||n!=len(payload){t.Fatalf("write %d %v",n,err)}
	b:=make([]byte,4096)
	if n,err:=c.Read(b);err!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("read %d %v",n,err)}
	c.Close()
	if _,err:=c.Read(b);!errors.Is(err,net.ErrClosed){t.Fatal(err)}
}
func TestLXFinalMaskXDNSDoHValidation(t *testing.T){
	for _,s:=range []string{
		strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","https://127.0.0.1",1),
		strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","http://127.0.0.1/dns-query",1),
		strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","https://127.0.0.1/dns-query?x=1",1),
	}{
		if _,err:=compileXDNS(json.RawMessage(s));err==nil{t.Fatalf("accepted %s",s)}
	}
	cfg,err:=compileXDNS(json.RawMessage(strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","https://127.0.0.1/dns-query",1)))
	if err!=nil{t.Fatal(err)}
	if cfg.resolver!=M.ParseSocksaddr("127.0.0.1:443"){t.Fatal("bad default port")}
	c:=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _,err:=c.Read(make([]byte,20));!errors.Is(err,os.ErrDeadlineExceeded){t.Fatal(err)}
}
func TestLXFinalMaskXDNSDoHRejectTLSAndOversize(t *testing.T){
	s:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		w.Header().Set("Content-Type","application/dns-message");w.Write(make([]byte,4097))
	}))
	defer s.Close()
	cfg,err:=compileXDNS(json.RawMessage(strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353",s.URL+"/dns-query",1)))
	if err!=nil{t.Fatal(err)}
	c:=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg)
	defer c.Close()
	if _,err:=c.exchange(make([]byte,12));err==nil{t.Fatal("untrusted certificate accepted")}
	roots:=x509.NewCertPool();roots.AddCert(s.Certificate())
	c.Close()
	c=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg);defer c.Close()
	c.transport.TLSClientConfig.RootCAs=roots
	if _,err:=c.exchange(make([]byte,12));err==nil{t.Fatal("oversized response accepted")}
}

func TestLXFinalMaskXDNSDoH3Validation(t *testing.T){
	raw:=strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","https://127.0.0.1/dns-query",1)
	raw=strings.Replace(raw,`"addrs":[`,`"tlsConfig":{"alpn":["h3"]},"addrs":[`,1)
	cfg,err:=compileXDNS(json.RawMessage(raw))
	if xdnsDoH3Available{
		if err!=nil||!cfg.dohH3{t.Fatalf("valid h3 rejected %v",err)}
	}else if err==nil{t.Fatal("h3 accepted without QUIC")}
	raw=strings.Replace(raw,`["h3"]`,`["h3","h2"]`,1)
	if _,err:=compileXDNS(json.RawMessage(raw));err==nil{t.Fatal("mixed h3 accepted")}
}

func TestLXFinalMaskXDNSBootstrapHost(t *testing.T){
	payload:=bytes.Repeat([]byte{3},32)
	s:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if !strings.HasPrefix(r.Host,"example.com:")||r.TLS.ServerName!="example.com"{w.WriteHeader(400);return}
		b,e:=io.ReadAll(r.Body)
		if e!=nil||!bytes.Equal(b,payload){w.WriteHeader(400);return}
		w.Header().Set("Content-Type","application/dns-message");w.Write(b)
	}))
	defer s.Close()
	// The httptest certificate covers example.com, and the dial target
	// is explicitly loopback, so no external DNS is needed.
	hostURL:=strings.Replace(s.URL,"127.0.0.1","example.com",1)+"/dns-query"
	raw:=strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353",hostURL,1)
	if _,e:=compileXDNS(json.RawMessage(raw));e==nil{t.Fatal("implicit bootstrap accepted")}
	raw=strings.Replace(raw,`"addrs":[`,`"bootstrapIP":"127.0.0.1","addrs":[`,1)
	cfg,e:=compileXDNS(json.RawMessage(raw))
	if e!=nil{t.Fatal(e)}
	if cfg.dohServerName!="example.com"||cfg.resolver.Addr.String()!="127.0.0.1"||cfg.dohURL!=hostURL{t.Fatal("bootstrap mapping incorrect")}
	c:=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg);defer c.Close()
	roots:=x509.NewCertPool();roots.AddCert(s.Certificate())
	c.tlsConfig.RootCAs=roots
	got,e:=c.exchange(payload)
	if e!=nil||!bytes.Equal(got,payload){t.Fatalf("exchange %x %v",got,e)}
	for _,bad:=range []string{
		strings.Replace(raw,"example.com","-example.com",1),
		strings.Replace(raw,`"bootstrapIP":"127.0.0.1"`,`"bootstrapIP":"0.0.0.0"`,1),
		strings.Replace(raw,"example.com","127.0.0.1",1),
		strings.Replace(raw,`"addrs":[`,`"quicConfig":{},"addrs":[`,1),
	}{
		if _,e=compileXDNS(json.RawMessage(bad));e==nil{t.Fatal("invalid bootstrap/QUIC config accepted")}
	}
}
