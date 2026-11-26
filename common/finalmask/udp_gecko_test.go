package finalmask

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"
)

func TestLXFinalMaskGeckoReference(t *testing.T){
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{t.Fatal(err)}
	defer raw.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	raw.SetDeadline(time.Now().Add(time.Second))
	m,err:=NewUDPChain(udpOpts(`{"password":"test-key","packetSize":"512-1200"}`))
	if err!=nil{t.Fatal(err)}
	c:=m.WrapConnected(raw)
	payload:=bytes.Repeat([]byte{0xc0,0x45,0x67},400)
	if n,err:=c.Write(payload);n!=len(payload)||err!=nil{t.Fatalf("write %d %v",n,err)}
	var parts [8][]byte
	var addr *net.UDPAddr
	count:=0
	for i:=0;i==0||i<count;i++{
		wire:=make([]byte,4096)
		n,a,e:=peer.ReadFromUDP(wire);if e!=nil{t.Fatal(e)};addr=a
		if n<512||n>1200{t.Fatalf("padding bounds %d",n)}
		key:=blake2b.Sum256(append([]byte("test-key"),wire[:8]...))
		frame:=wire[8:n];for j:=range frame{frame[j]^=key[j%32]}
		if frame[0]!=0x80{t.Fatal("missing fragment marker")}
		if i==0{count=int(frame[2]&15)}
		if count<2||count>8||int(frame[2]>>4)>=count{t.Fatal("bad index")}
		pad:=int(binary.BigEndian.Uint16(frame[3:5]))
		parts[frame[2]>>4]=bytes.Clone(frame[5+pad:])
	}
	if !bytes.Equal(bytes.Join(parts[:count],nil),payload){t.Fatal("wire mismatch")}
	send:=func(frame []byte){
		t.Helper()
		salt:=[]byte{1,2,3,4,5,6,7,8}
		key:=blake2b.Sum256(append([]byte("test-key"),salt...))
		wire:=append(bytes.Clone(salt),frame...)
		for j:=range frame{wire[8+j]^=key[j%32]}
		if _,e:=peer.WriteToUDP(wire,addr);e!=nil{t.Fatal(e)}
	}
	send([]byte{0x80,7,0x12,0,1,0,3,4})
	send([]byte{0x80,7,0x12,0,0,99}) // duplicate
	send([]byte{0x80,7,0x02,0,0,0xc0,2})
	out:=make([]byte,100)
	n,err:=c.Read(out)
	if err!=nil||!bytes.Equal(out[:n],[]byte{0xc0,2,3,4}){t.Fatalf("read %x %v",out[:n],err)}
	send([]byte{0x40,9,8})
	n,err=c.Read(out)
	if err!=nil||!bytes.Equal(out[:n],[]byte{0x40,9,8}){t.Fatalf("short header %x %v",out[:n],err)}
}

func TestLXFinalMaskGeckoReassemblyLimits(t *testing.T){
	c:=&geckoUDPConn{}
	now:=time.Now()
	dst:=make([]byte,geckoMaxPayload)
	for i:=0;i<geckoSlots;i++{if _,ok:=c.accept(dst,uint8(i),0,2,[]byte{1},now);ok{t.Fatal("partial complete")}}
	c.accept(dst,99,0,2,[]byte{1},now)
	for _,s:=range c.slots{if s.id==99{t.Fatal("slot limit exceeded")}}
	later:=now.Add(geckoTTL)
	c.accept(dst,99,0,2,[]byte{1},later)
	if n,ok:=c.accept(dst,99,1,2,[]byte{2},later);!ok||n!=2{t.Fatal("expired slots not reclaimed")}
	c.accept(dst,42,0,2,make([]byte,geckoMaxPayload),later)
	if _,ok:=c.accept(dst,42,1,2,[]byte{1},later);ok{t.Fatal("oversized assembly")}
	for _,s:=range c.slots{if s.used&&s.id==42{t.Fatal("oversized slot retained")}}
}
