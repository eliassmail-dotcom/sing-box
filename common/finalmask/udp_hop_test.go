package finalmask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func hopPeer(t *testing.T)*net.UDPConn{
	t.Helper()
	p,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if e!=nil{t.Fatal(e)}
	t.Cleanup(func(){p.Close()})
	p.SetDeadline(time.Now().Add(4*time.Second))
	return p
}
func hopReceive(t *testing.T,p *net.UDPConn,want string)*net.UDPAddr{
	t.Helper()
	b:=make([]byte,4096)
	n,a,e:=p.ReadFromUDP(b)
	if e!=nil||!bytes.Equal(b[:n],[]byte(want)){t.Fatalf("peer read %q %v",b[:n],e)}
	return a
}
func hopRead(t *testing.T,c net.Conn,want string){
	t.Helper()
	b:=make([]byte,4096)
	n,e:=c.Read(b)
	if e!=nil||string(b[:n])!=want{t.Fatalf("client read %q %v",b[:n],e)}
}
func TestLXFinalMaskUDPHopLocal(t *testing.T){
	p:=hopPeer(t)
	cfg,e:=compileUDPHop(json.RawMessage(`{"mode":"intervalLocal","interval":3600}`))
	if e!=nil{t.Fatal(e)}
	raw,e:=dialUDPHop(context.Background(),N.SystemDialer,M.ParseSocksaddr(p.LocalAddr().String()),cfg)
	if e!=nil{t.Fatal(e)}
	c:=raw.(*udpHopConn);defer c.Close()
	c.SetDeadline(time.Now().Add(3*time.Second))
	if _,e=c.Write([]byte("first"));e!=nil{t.Fatal(e)}
	a:=hopReceive(t,p,"first")
	c.hop()
	if _,e=c.Write([]byte("second"));e!=nil{t.Fatal(e)}
	b:=hopReceive(t,p,"second")
	if a.Port==b.Port{t.Fatal("local port did not change")}
	if _,e=p.WriteToUDP([]byte("late"),a);e!=nil{t.Fatal(e)}
	hopRead(t,c,"late")
	if _,e=p.WriteToUDP([]byte("new"),b);e!=nil{t.Fatal(e)}
	hopRead(t,c,"new")
	c.hop()
	if _,e=c.Write([]byte("third"));e!=nil{t.Fatal(e)}
	d:=hopReceive(t,p,"third")
	if d.Port==b.Port{t.Fatal("second rotation failed")}
	c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _,e=c.Read(make([]byte,64));!errors.Is(e,os.ErrDeadlineExceeded){t.Fatal(e)}
	c.SetReadDeadline(time.Now().Add(time.Second))
	if _,e=p.WriteToUDP([]byte("recover"),d);e!=nil{t.Fatal(e)}
	hopRead(t,c,"recover")
	c.Close()
	if _,e=c.Write([]byte("closed"));!errors.Is(e,net.ErrClosed){t.Fatal(e)}
}
func TestLXFinalMaskUDPHopRemote(t *testing.T){
	a,b:=hopPeer(t),hopPeer(t)
	cfg,e:=compileUDPHop(json.RawMessage(`{"mode":"intervalRemote","interval":3600}`))
	if e==nil{t.Fatal("remote without targets accepted")}
	cfg=&udpHopConfig{remote:true,min:3600,max:3600,ports:[]uint16{uint16(a.LocalAddr().(*net.UDPAddr).Port)}}
	raw,e:=dialUDPHop(context.Background(),N.SystemDialer,M.ParseSocksaddr(a.LocalAddr().String()),cfg)
	if e!=nil{t.Fatal(e)}
	c:=raw.(*udpHopConn);defer c.Close()
	c.SetDeadline(time.Now().Add(3*time.Second))
	if _,e=c.Write([]byte("first"));e!=nil{t.Fatal(e)}
	first:=hopReceive(t,a,"first")
	// Test-only update, before the manual hop; the real config is immutable.
	c.hopMu.Lock();cfg.ports=[]uint16{uint16(b.LocalAddr().(*net.UDPAddr).Port)};c.hopMu.Unlock()
	c.hop()
	if _,e=c.Write([]byte("second"));e!=nil{t.Fatal(e)}
	second:=hopReceive(t,b,"second")
	if first.Port!=second.Port{t.Fatal("remote-only changed local socket")}
	if _,e=a.WriteToUDP([]byte("late"),first);e!=nil{t.Fatal(e)}
	hopRead(t,c,"late")
	if _,e=b.WriteToUDP([]byte("new"),second);e!=nil{t.Fatal(e)}
	hopRead(t,c,"new")
}
func TestLXFinalMaskUDPHopOnce(t *testing.T){
	p:=hopPeer(t)
	cfg:=&udpHopConfig{once:true,min:30,max:30,ports:[]uint16{uint16(p.LocalAddr().(*net.UDPAddr).Port)}}
	c,e:=dialUDPHop(context.Background(),N.SystemDialer,M.ParseSocksaddr("127.0.0.1:1"),cfg)
	if e!=nil{t.Fatal(e)}
	defer c.Close()
	if _,ok:=c.(*udpHopConn);ok{t.Fatal("unnecessary hopping workers")}
	if _,e=c.Write([]byte("once"));e!=nil{t.Fatal(e)}
	hopReceive(t,p,"once")
}
func TestLXFinalMaskUDPHopValidation(t *testing.T){
	for _,s:=range []string{
		`{"mode":"unknown"}`,`{"mode":"intervalLocal","interval":4}`,
		`{"mode":"intervalRemote","remotePorts":"1-1000"}`,
		`{"mode":"perConnRemote","remoteIPs":["0.0.0.0/0"]}`,
		`{"mode":"intervalLocal","remotePorts":443}`,
	}{
		if _,e:=compileUDPHop(json.RawMessage(s));e==nil{t.Fatalf("accepted %s",s)}
	}
	o:=option.LXFinalMaskUDPMaskOptions{Type:"udphop",Settings:json.RawMessage(`{"mode":"intervalLocal,intervalRemote","interval":"5-30","remotePorts":"443,5000-5002","remoteIPs":["192.0.2.0/24"]}`)}
	m,e:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{o})
	if e!=nil||!m.ReplacesCarrier(){t.Fatalf("valid config %v",e)}
	cfg:=m.masks[0].hop
	for i:=0;i<100;i++{
		a:=cfg.target(M.ParseSocksaddr("192.0.2.1:443"))
		if !cfg.prefixes[0].Contains(a.Addr){t.Fatal("target outside prefix")}
	}
	if _,e:=NewUDPChain(append([]option.LXFinalMaskUDPMaskOptions{o},udpOpts(`{"password":"test-key"}`)[0]));e==nil{t.Fatal("composition accepted")}
}
