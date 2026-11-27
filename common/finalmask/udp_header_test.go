package finalmask

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)
func udpHeaderOpts(s string)[]option.LXFinalMaskUDPMaskOptions{
	return []option.LXFinalMaskUDPMaskOptions{{Type:"header-custom",Settings:json.RawMessage(s)}}
}
func TestLXFinalMaskUDPHeaderPrefix(t *testing.T){
	m,err:=NewUDPChain(udpHeaderOpts(`{"mode":"prefix","client":[{"packet":[1,2]},{"rand":3,"randRange":"7-7","capture":"v"},{"reuse":"v"}],"server":[{"packet":[9]},{"transform":{"op":"concat","args":[{"reuse":"v"},{"bytes":[8]}]}}]}`))
	if err!=nil{t.Fatal(err)}
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{t.Fatal(err)}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(time.Second))
	peer.SetDeadline(time.Now().Add(time.Second))
	c:=m.WrapConnected(raw)
	if n,err:=c.Write([]byte("data"));n!=4||err!=nil{t.Fatalf("write %d %v",n,err)}
	wire:=make([]byte,4096)
	n,addr,err:=peer.ReadFromUDP(wire)
	if err!=nil||!bytes.Equal(wire[:n],append([]byte{1,2,7,7,7,7,7,7},[]byte("data")...)){t.Fatalf("wire %x %v",wire[:n],err)}
	for _,p:=range [][]byte{{9},{9,7,7,6,8,99},{9,7,7,7,8,4,5}}{
		if _,err:=peer.WriteToUDP(p,addr);err!=nil{t.Fatal(err)}
	}
	n,err=c.Read(wire)
	if err!=nil||!bytes.Equal(wire[:n],[]byte{4,5}){t.Fatalf("read %x %v",wire[:n],err)}
}
func TestLXFinalMaskUDPHeaderValidation(t *testing.T){
	for _,s:=range []string{
		`{}`,`{"mode":"standalone","client":[{"packet":[1]}]}`,
		`{"client":[{"rand":513}]}`,`{"client":[{"delay":10,"packet":[1]}]}`,
		`{"client":[{"reuse":"missing"}]}`,
		`{"server":[{"transform":{"op":"be16","args":[{"metadata":"local_port"}]}}]}`,
	}{
		if _,err:=NewUDPChain(udpHeaderOpts(s));err==nil{t.Fatalf("accepted %s",s)}
	}
}
func TestLXFinalMaskUDPHeaderState(t *testing.T){
	m,err:=NewUDPChain(udpHeaderOpts(`{"client":[{"rand":2,"randRange":"4-4","capture":"v"}],"server":[{"rand":1,"capture":"s"},{"reuse":"v"}]}`))
	if err!=nil{t.Fatal(err)}
	a:=m.WrapConnected(&capture{}).(*udpHeaderConn)
	b:=m.WrapConnected(&capture{}).(*udpHeaderConn)
	if _,err:=a.Write([]byte{1});err!=nil{t.Fatal(err)}
	if b.match([]byte{3,4,4}){t.Fatal("state shared across connections")}
	if a.match([]byte{7,4,5}){t.Fatal("mismatch accepted")}
	if _,ok:=a.vars["s"];ok{t.Fatal("failed match committed state")}
	if !a.match([]byte{3,4,4}){t.Fatal("valid reply rejected")}
	a.expires=time.Now().Add(-time.Second)
	if a.match([]byte{3,4,4}){t.Fatal("expired state accepted")}
}
func TestLXFinalMaskUDPHeaderOrder(t *testing.T){
	header:=udpHeaderOpts(`{"client":[{"packet":[1,2]}]}`)[0]
	noise:=noiseOptions(`{"noise":[{"packet":[3]}]}`)[0]
	for _,tc:=range []struct{opts []option.LXFinalMaskUDPMaskOptions;first []byte}{
		{[]option.LXFinalMaskUDPMaskOptions{header,noise},[]byte{3}},
		{[]option.LXFinalMaskUDPMaskOptions{noise,header},[]byte{1,2,3}},
	}{
		m,err:=NewUDPChain(tc.opts);if err!=nil{t.Fatal(err)}
		raw:=&capture{}
		if _,err:=m.WrapConnected(raw).Write([]byte{9});err!=nil{t.Fatal(err)}
		if len(raw.writes)!=2||!bytes.Equal(raw.writes[0],tc.first)||!bytes.Equal(raw.writes[1],[]byte{1,2,9}){t.Fatalf("bad order %x",raw.writes)}
	}
}
