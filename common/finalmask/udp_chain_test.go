package finalmask

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/crypto/blake2b"
)

func udpOpts(s string)[]option.LXFinalMaskUDPMaskOptions{return []option.LXFinalMaskUDPMaskOptions{{Type:"salamander",Settings:json.RawMessage(s)}}}

func TestLXFinalMaskUDPSalamanderValidation(t *testing.T){
	if c,err:=NewUDPChain(nil);c!=nil||err!=nil{t.Fatalf("default changed %v %v",c,err)}
	for _,s:=range []string{`{}`,`{"password":"abc"}`,`{"password":"secret","packetSize":"512-1200"}`,`{"password":"secret","typo":1}`}{
		if _,err:=NewUDPChain(udpOpts(s));err==nil{t.Fatalf("accepted %s",s)}
	}
	if _,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{{Type:"noise",Settings:json.RawMessage("{}")}});err==nil{t.Fatal("accepted noise")}
}

// A reference peer independently constructs and decodes the Xray wire
// layout with the pinned algorithm, over real localhost UDP sockets.
func TestLXFinalMaskUDPSalamanderReference(t *testing.T){
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{t.Fatal(err)}
	defer raw.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	raw.SetDeadline(time.Now().Add(time.Second))
	mask,err:=NewUDPChain(udpOpts(`{"password":"test-key"}`));if err!=nil{t.Fatal(err)}
	c:=mask.WrapConnected(raw)
	payload:=bytes.Repeat([]byte{0x45,0x23,0x67},400)
	original:=bytes.Clone(payload)
	if n,err:=c.Write(payload);err!=nil||n!=len(payload){t.Fatalf("write %d %v",n,err)}
	wire:=make([]byte,4096)
	n,addr,err:=peer.ReadFromUDP(wire)
	if err!=nil||n!=len(payload)+8{t.Fatalf("wire %d %v",n,err)}
	key:=blake2b.Sum256(append([]byte("test-key"),wire[:8]...))
	for i,b:=range wire[8:n]{if b^key[i%32]!=payload[i]{t.Fatal("bad wire payload")}}
	if !bytes.Equal(payload,original){t.Fatal("caller bytes changed")}
	if _,err:=peer.WriteToUDP([]byte{1,2,3},addr);err!=nil{t.Fatal(err)}
	reply:=[]byte("reference reply")
	salt:=[]byte{1,2,3,4,5,6,7,8}
	key=blake2b.Sum256(append([]byte("test-key"),salt...))
	frame:=append(bytes.Clone(salt),reply...)
	for i:=range reply{frame[8+i]^=key[i%32]}
	if _,err:=peer.WriteToUDP(frame,addr);err!=nil{t.Fatal(err)}
	buf:=make([]byte,100)
	n,err=c.Read(buf)
	if err!=nil||!bytes.Equal(buf[:n],reply){t.Fatalf("read %q %v",buf[:n],err)}
	if _,err:=c.Write(make([]byte,4090));err==nil{t.Fatal("oversized datagram accepted")}
	if _,err:=c.Write([]byte("ok"));err!=nil{t.Fatal(err)}
}

type udpShortConn struct{ net.Conn }
func(*udpShortConn)Write(p []byte)(int,error){return len(p)-1,nil}
func TestLXFinalMaskUDPShortWrite(t *testing.T){
	m,err:=NewUDPChain(udpOpts(`{"password":"test-key"}`));if err!=nil{t.Fatal(err)}
	if n,err:=m.WrapConnected(&udpShortConn{}).Write([]byte("data"));n!=0||err!=io.ErrShortWrite{t.Fatalf("%d %v",n,err)}
}
