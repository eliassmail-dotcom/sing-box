package finalmask

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func TestLXFinalMaskXICMPReference(t *testing.T){
	for _,v6:=range []bool{false,true}{
		network,host:="udp4","127.0.0.1:0"
		proto:=1
		request,reply:=icmp.Type(ipv4.ICMPTypeEcho),icmp.Type(ipv4.ICMPTypeEchoReply)
		if v6{network,host="udp6","[::1]:0";proto=58;request,reply=ipv6.ICMPTypeEchoRequest,ipv6.ICMPTypeEchoReply}
		raw,err:=net.ListenPacket(network,host)
		if err!=nil{if v6{t.Log("IPv6 loopback unavailable");continue};t.Fatal(err)}
		peer,err:=net.ListenPacket(network,host);if err!=nil{raw.Close();t.Fatal(err)}
		c,err:=newXICMPConn(raw,xicmpPeer(peer.LocalAddr()),true);if err!=nil{raw.Close();peer.Close();t.Fatal(err)}
		c.target=peer.LocalAddr() // local reference peer, no privileged ICMP sockets
		deadline:=time.Now().Add(2*time.Second)
		c.SetDeadline(deadline);peer.SetDeadline(deadline)
		p:=bytes.Repeat([]byte{42},1200)
		if n,e:=c.Write(p);e!=nil||n!=len(p){t.Fatalf("write %d %v",n,e)}
		var b [4097]byte
		n,addr,e:=peer.ReadFrom(b[:]);if e!=nil{t.Fatal(e)}
		m,e:=icmp.ParseMessage(proto,b[:n]);if e!=nil||m.Type!=request{t.Fatalf("request %v %v",m,e)}
		echo:=m.Body.(*icmp.Echo)
		if echo.Seq!=1||!bytes.Equal(echo.Data[:8],c.clientID[:])||!bytes.Equal(echo.Data[8:],p){t.Fatal("bad Xray echo payload")}
		// The ordinary kernel echo reply must be ignored.
		m.Type=reply
		own,e:=m.Marshal(nil);if e!=nil{t.Fatal(e)}
		if _,e=peer.WriteTo(own,addr);e!=nil{t.Fatal(e)}
		// Server response carries payload only, not our client ID.
		echo.Data=p
		wire,e:=m.Marshal(nil);if e!=nil{t.Fatal(e)}
		if _,e=peer.WriteTo(wire,addr);e!=nil{t.Fatal(e)}
		n,e=c.Read(b[:]);if e!=nil||!bytes.Equal(b[:n],p){t.Fatalf("read %d %v",n,e)}
		if _,e=c.Write(make([]byte,xicmpMaxPayload+1));e==nil{t.Fatal("oversize accepted")}
		c.Close();peer.Close()
	}
}

func TestLXFinalMaskXICMPValidation(t *testing.T){
	for _,s:=range []string{
		`{"ips":["example.com"]}`,`{"ips":["0.0.0.0"]}`,`{"ips":["224.0.0.1"]}`,
		`{"ips":["fe80::1"]}`,`{"ips":["127.0.0.1","::ffff:127.0.0.1"]}`,
		`{"ips":["1.1.1.1","1.1.1.2","1.1.1.3","1.1.1.4","1.1.1.5"]}`,
	}{
		if _,e:=compileXICMP(json.RawMessage(s));e==nil{t.Fatalf("accepted %s",s)}
	}
	m,e:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{{Type:"xicmp",Settings:json.RawMessage(`{"dgram":true,"ips":["127.0.0.1"]}`)}})
	if e!=nil||!m.ReplacesCarrier()||m.DialNetwork()!="icmp"{t.Fatalf("invalid XICMP chain %v",e)}
	if _,e=m.DialCarrier(context.Background(),N.SystemDialer,M.ParseSocksaddr("127.0.0.1:443"));e==nil{t.Fatal("unprotected fallback accepted")}
}

type testXICMPDialer struct{
	N.Dialer
	conn net.PacketConn
	called bool
}
func(d *testXICMPDialer)ListenXICMP(_ context.Context,ip netip.Addr,dgram bool)(net.PacketConn,error){
	d.called=ip==netip.MustParseAddr("127.0.0.1")&&dgram
	return d.conn,nil
}
func TestLXFinalMaskXICMPDialCapability(t *testing.T){
	raw,e:=net.ListenPacket("udp4","127.0.0.1:0");if e!=nil{t.Fatal(e)}
	defer raw.Close()
	d:=&testXICMPDialer{conn:raw}
	cfg,e:=compileXICMP(json.RawMessage(`{"dgram":true}`));if e!=nil{t.Fatal(e)}
	c,e:=dialXICMP(context.Background(),d,M.ParseSocksaddr("127.0.0.1:443"),cfg)
	if e!=nil||!d.called{t.Fatalf("capability not used: %v",e)}
	c.Close()
}
