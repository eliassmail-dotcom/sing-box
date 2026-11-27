package finalmask

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"hash/fnv"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func legacyOpts(s string)[]option.LXFinalMaskUDPMaskOptions{
	return []option.LXFinalMaskUDPMaskOptions{{Type:"mkcp-legacy",Settings:json.RawMessage(s)}}
}
func TestLXFinalMaskUDPLegacyHeaders(t *testing.T){
	for _,tc:=range []struct{json string;first,second []byte}{
		{`{"header":"dtls"}`,[]byte{23,254,253,0,0,0,0,0,0,0,0,0,0},[]byte{23,254,253,0,0,0,0,0,0,0,1,0,17}},
		{`{"header":"srtp"}`,[]byte{0,0,0,1},[]byte{0,0,0,2}},
		{`{"header":"utp"}`,[]byte{0,0,0,0},[]byte{0,0,0,0}},
		{`{"header":"wechat"}`,[]byte{0xa1,8,0,0,0,1,0,16,17,24,48,34,48},[]byte{0xa1,8,0,0,0,2,0,16,17,24,48,34,48}},
		{`{"header":"wireguard"}`,[]byte{4,0,0,0},[]byte{4,0,0,0}},
	}{
		m,err:=NewUDPChain(legacyOpts(tc.json));if err!=nil{t.Fatal(err)}
		raw:=&capture{}
		c:=m.WrapConnected(raw)
		for _,want:=range [][]byte{tc.first,tc.second}{
			if _,err:=c.Write([]byte{99});err!=nil{t.Fatal(err)}
			got:=raw.writes[len(raw.writes)-1]
			if !bytes.Equal(got,append(bytes.Clone(want),99)){t.Fatalf("%s got %x",tc.json,got)}
		}
	}
	cfg,err:=compileUDPLegacy(json.RawMessage(`{"header":"dns","value":"a.test"}`))
	if err!=nil{t.Fatal(err)}
	c:=&udpLegacyConn{config:cfg}
	b,err:=c.encode([]byte{99})
	want:=[]byte{1,0,0,1,0,0,0,0,0,0,1,'a',4,'t','e','s','t',0,0,1,0,1,99}
	if err!=nil||!bytes.Equal(b[2:],want){t.Fatalf("DNS %x %v",b,err)}
}

func TestLXFinalMaskUDPLegacyOriginalAES(t *testing.T){
	for _,s:=range []string{`{}`,`{"value":"secret"}`}{
		m,err:=NewUDPChain(legacyOpts(s));if err!=nil{t.Fatal(err)}
		peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
		if err!=nil{t.Fatal(err)}
		raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
		if err!=nil{peer.Close();t.Fatal(err)}
		c:=m.WrapConnected(raw)
		c.SetDeadline(time.Now().Add(time.Second));peer.SetDeadline(time.Now().Add(time.Second))
		for _,payload:=range [][]byte{{1},{2,3,4},bytes.Repeat([]byte{5},1201)}{
			if n,err:=c.Write(payload);err!=nil||n!=len(payload){t.Fatalf("write %d %v",n,err)}
			wire:=make([]byte,4096)
			n,addr,err:=peer.ReadFromUDP(wire);if err!=nil{t.Fatal(err)}
			frame:=wire[:n]
			var decoded []byte
			if s=="{}"{
				if n!=len(payload)+6{t.Fatal("bad original width")}
				tmp:=bytes.Clone(frame)
				for i:=len(tmp)-1;i>=4;i--{tmp[i]^=tmp[i-4]}
				h:=fnv.New32a();h.Write(tmp[4:])
				if binary.BigEndian.Uint32(tmp)!=h.Sum32()||int(binary.BigEndian.Uint16(tmp[4:]))!=len(payload){t.Fatal("bad original auth")}
				decoded=tmp[6:]
			}else{
				key:=sha256.Sum256([]byte("secret"));block,_:=aes.NewCipher(key[:16]);a,_:=cipher.NewGCM(block)
				decoded,err=a.Open(nil,frame[:12],frame[12:],nil)
				if err!=nil{t.Fatal(err)}
			}
			if !bytes.Equal(decoded,payload){t.Fatal("wire mismatch")}
			invalid:=bytes.Clone(frame);invalid[len(invalid)-1]^=1
			for _,packet:=range [][]byte{{1},invalid,frame}{
				if _,err:=peer.WriteToUDP(packet,addr);err!=nil{t.Fatal(err)}
			}
			b:=make([]byte,2048)
			n,err=c.Read(b)
			if err!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("read %x %v",b[:n],err)}
		}
		if _,err:=c.Write(make([]byte,4096));err==nil{t.Fatal("oversized accepted")}
		c.Close();peer.Close()
	}
}
func TestLXFinalMaskUDPLegacyReject(t *testing.T){
	for _,s:=range []string{`{"header":"unknown"}`,`{"header":"dns","value":"a..b"}`,`{"typo":1}`}{
		if _,err:=NewUDPChain(legacyOpts(s));err==nil{t.Fatalf("accepted %s",s)}
	}
	if _,err:=NewUDPChain(append(legacyOpts("{}"),udpOpts(`{"password":"test-key"}`)[0]));err==nil{t.Fatal("accepted unvalidated composition")}
}
