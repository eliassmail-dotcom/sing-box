//go:build with_quic

package finalmask

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/quic-go/http3"
	N "github.com/sagernet/sing/common/network"
)

func TestLXFinalMaskXDNSDoH3Exchange(t *testing.T){
	// Reuse the standard library's test certificate, trusted only by
	// this test client. HTTP/3 is served on a separate real UDP socket.
	certServer:=httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter,*http.Request){}))
	defer certServer.Close()
	cert:=certServer.TLS.Certificates[0]
	roots:=x509.NewCertPool()
	roots.AddCert(certServer.Certificate())
	packet,err:=net.ListenPacket("udp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	defer packet.Close()
	payload:=bytes.Repeat([]byte{7},32)
	server:=&http3.Server{
		TLSConfig:http3.ConfigureTLSConfig(&tls.Config{Certificates:[]tls.Certificate{cert}}),
		Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
			if r.ProtoMajor!=3||r.Method!="POST"||r.Header.Get("Content-Type")!="application/dns-message"{w.WriteHeader(400);return}
			b,err:=io.ReadAll(io.LimitReader(r.Body,4097))
			if err!=nil||!bytes.Equal(b,payload){w.WriteHeader(400);return}
			w.Header().Set("Content-Type","application/dns-message")
			w.Write(b)
		}),
	}
	done:=make(chan struct{})
	go func(){defer close(done);_ = server.Serve(packet)}()
	defer func(){server.Close();packet.Close();select{case <-done:case <-time.After(3*time.Second):t.Error("server shutdown timed out")}}()
	raw:=strings.Replace(xdnsTestConfig,"udp://127.0.0.1:5353","https://"+packet.LocalAddr().String()+"/dns-query",1)
	raw=strings.Replace(raw,`"addrs":[`,`"tlsConfig":{"alpn":["h3"]},"addrs":[`,1)
	cfg,err:=compileXDNS(json.RawMessage(raw))
	if err!=nil{t.Fatal(err)}
	if !cfg.dohH3{t.Fatal("HTTP/3 not selected")}
	untrusted:=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg)
	if _,err:=untrusted.exchange(payload);err==nil{untrusted.Close();t.Fatal("untrusted certificate accepted")}
	untrusted.Close()
	c:=newXDNSDoHConn(context.Background(),N.SystemDialer,cfg)
	defer c.Close()
	c.tlsConfig.RootCAs=roots
	c.SetDeadline(time.Now().Add(5*time.Second))
	if n,e:=c.Write(payload);e!=nil||n!=len(payload){t.Fatalf("write %d %v",n,e)}
	b:=make([]byte,4096)
	if n,e:=c.Read(b);e!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("read %d %v",n,e)}
	c.Close()
	if _,e:=c.Read(b);e==nil{t.Fatal("read after close succeeded")}
}
