package finalmask

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/dns/dnsmessage"
)

func multiSettings(addrs ...string)json.RawMessage{
	b,_:=json.Marshal(map[string]any{
		"domains":[]any{map[string]any{"names":[]string{"unit.test"},"edns0":4096}},
		"resolvers":[]any{map[string]any{"addrs":addrs}},
	})
	return b
}

func TestLXFinalMaskXDNSMultiSelection(t *testing.T){
	a,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer a.Close()
	b,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer b.Close()
	settings:=multiSettings(a.LocalAddr().String(),b.LocalAddr().String())
	m,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{{Type:"xdns",Settings:settings}})
	if err!=nil{t.Fatal(err)}
	raw,err:=m.DialCarrier(context.Background(),N.SystemDialer,M.ParseSocksaddr("192.0.2.1:443"))
	if err!=nil{t.Fatal(err)}
	c:=raw.(*xdnsMultiConn)
	defer c.Close()
	deadline:=time.Now().Add(3*time.Second)
	c.SetDeadline(deadline);a.SetDeadline(deadline);b.SetDeadline(deadline)
	cfg:=m.masks[0].xdns
	if len(cfg.alternates)!=1{t.Fatal("missing alternate")}
	query:=func(id uint16)[]byte{
		frames,e:=cfg.frames([8]byte{},1,[]byte{byte(id)})
		if e!=nil{t.Fatal(e)}
		wire,_,e:=cfg.query(id,frames[0]);if e!=nil{t.Fatal(e)}
		return wire
	}
	recv:=func(peer *net.UDPConn,want []byte,reply bool){
		buf:=make([]byte,4096)
		n,addr,e:=peer.ReadFromUDP(buf)
		if e!=nil||!bytes.Equal(buf[:n],want){t.Fatalf("resolver selection: %d %v",n,e)}
		if !reply{return}
		var q dnsmessage.Message
		if e=q.Unpack(buf[:n]);e!=nil{t.Fatal(e)}
		q.Header.Response=true
		wire,e:=q.Pack();if e!=nil{t.Fatal(e)}
		if _,e=peer.WriteToUDP(wire,addr);e!=nil{t.Fatal(e)}
	}
	q1,q2,q3:=query(1),query(2),query(3)
	if _,err=c.Write(q1);err!=nil{t.Fatal(err)}
	recv(a,q1,false)
	if _,err=c.Write(q2);err!=nil{t.Fatal(err)}
	recv(b,q2,true)
	if _,err=c.Read(make([]byte,4096));err!=nil{t.Fatal(err)}
	if _,err=c.Write(q3);err!=nil{t.Fatal(err)}
	recv(b,q3,true)
	if _,err=c.Read(make([]byte,4096));err!=nil{t.Fatal(err)}
	c.retire(1)
	q4:=query(4)
	if _,err=c.Write(q4);err!=nil{t.Fatal(err)}
	recv(a,q4,true)
	if _,err=c.Read(make([]byte,4096));err!=nil{t.Fatal(err)}
	c.retire(0)
	if _,err=c.Write(query(5));err==nil{t.Fatal("dead carriers accepted write")}
}

func TestLXFinalMaskXDNSMultiInitialFailure(t *testing.T){
	l,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
	addr:=l.Addr().String();l.Close()
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	cfg,err:=compileXDNS(multiSettings("tcp://"+addr,peer.LocalAddr().String()))
	if err!=nil{t.Fatal(err)}
	raw,err:=newXDNSMultiConn(context.Background(),N.SystemDialer,cfg)
	if err!=nil{t.Fatal(err)}
	defer raw.Close()
	if len(raw.(*xdnsMultiConn).slots)!=1{t.Fatal("failed resolver not excluded")}
}

func TestLXFinalMaskXDNSMultiValidation(t *testing.T){
	for _,a:=range [][]string{
		{"127.0.0.1","udp://127.0.0.1:53"},
		{"127.0.0.1","127.0.0.2","127.0.0.3","127.0.0.4"},
		{"https://127.0.0.1/dns-query","https://127.0.0.2/dns-query"},
	}{
		if _,err:=compileXDNS(multiSettings(a...));err==nil{t.Fatalf("accepted %v",a)}
	}
	settings:=json.RawMessage(fmt.Sprintf(`{"domains":[{"names":["unit.test"],"edns0":4096}],"resolvers":[{"addrs":["%s"],"worker":2},{"addrs":["%s"],"worker":2}]}`,"https://127.0.0.1/dns-query","https://127.0.0.2/dns-query"))
	cfg,err:=compileXDNS(settings)
	if err!=nil||len(cfg.alternates)!=1{t.Fatalf("valid worker budget %v",err)}
}
