package finalmask

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-quic/hysteria2/realm"
	N "github.com/sagernet/sing/common/network"
)

func TestLXFinalMaskRealmExchange(t *testing.T){
	stun,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer stun.Close()
	peer,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	deadline:=time.Now().Add(8*time.Second)
	stun.SetDeadline(deadline);peer.SetDeadline(deadline)
	stunDone:=make(chan error,1)
	go func(){
		var b [1500]byte
		n,a,e:=stun.ReadFromUDP(b[:])
		if e!=nil{stunDone<-e;return}
		if n<20||binary.BigEndian.Uint16(b[:2])!=1{stunDone<-fmt.Errorf("invalid STUN request");return}
		// Independent RFC 5389 XOR-MAPPED-ADDRESS response.
		r:=make([]byte,32)
		binary.BigEndian.PutUint16(r[:2],0x0101)
		binary.BigEndian.PutUint16(r[2:4],12)
		copy(r[4:20],b[4:20])
		binary.BigEndian.PutUint16(r[20:22],0x0020)
		binary.BigEndian.PutUint16(r[22:24],8)
		r[25]=1
		binary.BigEndian.PutUint16(r[26:28],uint16(a.Port)^0x2112)
		ip:=a.IP.To4()
		for i:=0;i<4;i++{r[28+i]=ip[i]^r[4+i]}
		_,e=stun.WriteToUDP(r,a)
		stunDone<-e
	}()
	metadata:=make(chan realm.PunchMetadata,1)
	server:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		if r.URL.Path!="/v1/unit/connect"||r.Method!="POST"||r.Header.Get("Authorization")!="Bearer test-token"{w.WriteHeader(400);return}
		var q struct{Addresses []string `json:"addresses"`;Nonce string `json:"nonce"`;Obfs string `json:"obfs"`}
		if json.NewDecoder(r.Body).Decode(&q)!=nil||len(q.Addresses)!=1{w.WriteHeader(400);return}
		nonce,e:=hex.DecodeString(q.Nonce);if e!=nil||len(nonce)!=16{w.WriteHeader(400);return}
		key,e:=hex.DecodeString(q.Obfs);if e!=nil||len(key)!=32{w.WriteHeader(400);return}
		var m realm.PunchMetadata
		copy(m.Nonce[:],nonce);copy(m.ObfuscationKey[:],key)
		metadata<-m
		w.Header().Set("Content-Type","application/json")
		json.NewEncoder(w).Encode(map[string]any{"addresses":[]string{peer.LocalAddr().String()},"nonce":q.Nonce,"obfs":q.Obfs})
	}))
	defer server.Close()
	peerDone:=make(chan error,1)
	go func(){
		var m realm.PunchMetadata
		select{case m=<-metadata:case <-time.After(8*time.Second):peerDone<-fmt.Errorf("no metadata");return}
		var b [4096]byte
		n,a,e:=peer.ReadFromUDP(b[:]);if e!=nil{peerDone<-e;return}
		typ,e:=realm.DecodePunchPacket(b[:n],m)
		if e!=nil||typ!=realm.PunchHello{peerDone<-fmt.Errorf("bad punch hello: %v",e);return}
		ack,e:=realm.EncodePunchPacket(realm.PunchAck,m);if e!=nil{peerDone<-e;return}
		if _,e=peer.WriteToUDP(ack,a);e!=nil{peerDone<-e;return}
		n,a,e=peer.ReadFromUDP(b[:]);if e!=nil{peerDone<-e;return}
		if !bytes.Equal(b[:n],[]byte("payload")){peerDone<-fmt.Errorf("bad payload");return}
		if _,e=peer.WriteToUDP(ack,a);e!=nil{peerDone<-e;return}
		_,e=peer.WriteToUDP([]byte("reply"),a);peerDone<-e
	}()
	settings,_:=json.Marshal(map[string]any{
		"url":"realm://test-token@"+strings.TrimPrefix(server.URL,"https://")+"/unit",
		"stunServers":[]string{stun.LocalAddr().String()},"ipMode":"v4",
	})
	cfg,err:=compileRealm(settings);if err!=nil{t.Fatal(err)}
	roots:=x509.NewCertPool();roots.AddCert(server.Certificate())
	ctx,cancel:=context.WithDeadline(context.Background(),deadline);defer cancel()
	c,err:=dialRealm(ctx,N.SystemDialer,cfg,roots)
	if err!=nil{t.Fatal(err)}
	defer c.Close()
	if err=<-stunDone;err!=nil{t.Fatal(err)}
	c.SetDeadline(deadline)
	if n,e:=c.Write([]byte("payload"));e!=nil||n!=7{t.Fatalf("write %d %v",n,e)}
	var b [4096]byte
	if n,e:=c.Read(b[:]);e!=nil||string(b[:n])!="reply"{t.Fatalf("read %d %v",n,e)}
	if err=<-peerDone;err!=nil{t.Fatal(err)}
}

func TestLXFinalMaskRealmValidation(t *testing.T){
	for _,s:=range []string{
		`{"url":"realm+http://token@127.0.0.1/unit","stunServers":["127.0.0.1:3478"]}`,
		`{"url":"realm://token@example.com/unit","stunServers":["127.0.0.1:3478"]}`,
		`{"url":"realm://token@127.0.0.1/unit","stunServers":["example.com:3478"]}`,
		`{"url":"realm://token@127.0.0.1/unit","stunServers":["127.0.0.1:3478"],"portMapping":{"enabled":true}}`,
		`{"url":"realm://token@127.0.0.1/unit","stunServers":["127.0.0.1:3478"],"tlsConfig":{"allowInsecure":true}}`,
		`{"url":"realm://token@127.0.0.1/unit","stunServers":["127.0.0.1:3478"],"ipMode":"v6"}`,
	}{
		if _,err:=compileRealm(json.RawMessage(s));err==nil{t.Fatal("invalid Realm config accepted")}
	}
}
