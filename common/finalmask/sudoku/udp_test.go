package sudoku

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestLXFinalMaskSudokuUDPReference(t *testing.T){
	for _,config:=range []Config{
		{Password:"test",Ascii:"prefer_ascii"},
		{Password:"test",Ascii:"prefer_entropy",PaddingMin:100,PaddingMax:100},
		{Password:"test",CustomTables:[]string{"xpxvvpvv","vxpvxvvp"},PaddingMin:20,PaddingMax:40},
	}{
		m,err:=New(&config)
		if err!=nil{t.Fatal(err)}
		peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
		if err!=nil{t.Fatal(err)}
		raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
		if err!=nil{peer.Close();t.Fatal(err)}
		c:=m.WrapUDP(raw)
		c.SetDeadline(time.Now().Add(3*time.Second))
		peer.SetDeadline(time.Now().Add(3*time.Second))
		// Two odd-sized packets catch accidental rotation across datagrams.
		for _,size:=range []int{1201,1451,2048}{
			payload:=make([]byte,size)
			for i:=range payload{payload[i]=byte(i)}
			if n,err:=c.Write(payload);err!=nil||n!=size{t.Fatalf("write %d %v",n,err)}
			wire:=make([]byte,udpEncodedLimit+1)
			n,addr,err:=peer.ReadFromUDP(wire)
			if err!=nil{t.Fatal(err)}
			idx:=0
			hints,decoded,err:=decodeBytes(m.tables,&idx,wire[:n],nil,nil)
			if err!=nil||len(hints)!=0||!bytes.Equal(decoded,payload){t.Fatalf("reference decode failed %v",err)}
			// Inject one incomplete hint before a valid reference packet.
			if _,err:=peer.WriteToUDP([]byte{m.tables[0].layout.encodeHint(0)},addr);err!=nil{t.Fatal(err)}
			// Oversized wire packet is discarded even when raw UDP truncates it.
			if _,err:=peer.WriteToUDP(make([]byte,udpEncodedLimit+10),addr);err!=nil{t.Fatal(err)}
			reply,err:=newCodec(m.tables,m.pMin,m.pMax).encode(payload)
			if err!=nil{t.Fatal(err)}
			if _,err:=peer.WriteToUDP(reply,addr);err!=nil{t.Fatal(err)}
			b:=make([]byte,udpPayloadLimit)
			n,err=c.Read(b)
			if err!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("reference reply %d %v",n,err)}
		}
		if _,err:=c.Write(make([]byte,udpPayloadLimit+1));err==nil{t.Fatal("oversized payload accepted")}
		c.Close()
		peer.Close()
	}
}

func TestLXFinalMaskSudokuUDPShortBufferAndDeadline(t *testing.T){
	m,err:=New(&Config{Password:"test"})
	if err!=nil{t.Fatal(err)}
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{t.Fatal(err)}
	c:=m.WrapUDP(raw)
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(-time.Millisecond))
	if _,err:=c.Read(make([]byte,2));err==nil{t.Fatal("deadline not honored")}
	c.SetReadDeadline(time.Now().Add(time.Second))
	for _,p:=range [][]byte{[]byte("too long"),[]byte("ok")}{
		b,err:=newCodec(m.tables,m.pMin,m.pMax).encode(p)
		if err!=nil{t.Fatal(err)}
		if _,err:=peer.WriteToUDP(b,raw.LocalAddr().(*net.UDPAddr));err!=nil{t.Fatal(err)}
	}
	b:=make([]byte,2)
	if n,err:=c.Read(b);err!=nil||n!=2||string(b)!="ok"{t.Fatalf("read %q %v",b,err)}
}
