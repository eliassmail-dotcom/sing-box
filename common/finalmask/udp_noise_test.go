package finalmask

import(
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/crypto/blake2b"
)
func noiseOptions(s string)[]option.LXFinalMaskUDPMaskOptions{
	return []option.LXFinalMaskUDPMaskOptions{{Type:"noise",Settings:json.RawMessage(s)}}
}
func TestLXFinalMaskUDPNoiseSequence(t *testing.T){
	m,err:=NewUDPChain(noiseOptions(`{"reset":1,"noise":[{"type":"hex","packet":"0102"},{"rand":3,"randRange":"7-7"},{"type":"exp","packet":"<b ff><c><rd 2><rc 2><r 2><n><t>"}]}`))
	if err!=nil{t.Fatal(err)}
	raw:=&capture{}
	c:=m.WrapConnected(raw).(*udpNoiseConn)
	if _,err:=c.Write([]byte("data"));err!=nil{t.Fatal(err)}
	if _,err:=c.Write([]byte("next"));err!=nil{t.Fatal(err)}
	if len(raw.writes)!=5||!bytes.Equal(raw.writes[0],[]byte{1,2})||!bytes.Equal(raw.writes[1],[]byte{7,7,7})||string(raw.writes[3])!="data"||string(raw.writes[4])!="next"{t.Fatalf("writes %x",raw.writes)}
	exp:=raw.writes[2]
	if len(exp)!=23||exp[0]!=255||binary.BigEndian.Uint32(exp[1:5])!=1{t.Fatalf("expr %x",exp)}
	for _,b:=range exp[5:7]{if b<'0'||b>'9'{t.Fatal("bad digit")}}
	for _,b:=range exp[7:9]{if !(b>='A'&&b<='Z'||b>='a'&&b<='z'){t.Fatal("bad letter")}}
	c.next=time.Now().Add(-time.Second)
	if _,err:=c.Write([]byte("reset"));err!=nil{t.Fatal(err)}
	if len(raw.writes)!=9||binary.BigEndian.Uint32(raw.writes[7][1:5])!=2{t.Fatal("idle reset not honored")}
}

func TestLXFinalMaskUDPNoiseOrder(t *testing.T){
	noise:=noiseOptions(`{"noise":[{"packet":[1,2,3]}]}`)[0]
	salamander:=udpOpts(`{"password":"test-key"}`)[0]
	for _,order:=range [][]option.LXFinalMaskUDPMaskOptions{{noise,salamander},{salamander,noise}}{
		m,err:=NewUDPChain(order)
		if err!=nil{t.Fatal(err)}
		raw:=&capture{}
		if _,err:=m.WrapConnected(raw).Write([]byte("data"));err!=nil{t.Fatal(err)}
		if len(raw.writes)!=2{t.Fatalf("got %d datagrams",len(raw.writes))}
		decode:=func(w []byte)[]byte{
			if len(w)<8{t.Fatal("short masked frame")}
			key:=blake2b.Sum256(append([]byte("test-key"),w[:8]...))
			b:=bytes.Clone(w[8:])
			for i:=range b{b[i]^=key[i%32]}
			return b
		}
		n:=raw.writes[0]
		if order[0].Type=="noise"{n=decode(n)}
		if !bytes.Equal(n,[]byte{1,2,3})||string(decode(raw.writes[1]))!="data"{t.Fatal("incorrect mask order")}
	}
}
func TestLXFinalMaskUDPNoiseValidation(t *testing.T){
	for _,s:=range []string{
		`{}`,`{"script":"return {}"}`,`{"noise":[{"rand":1201}]}`,`{"noise":[{"rand":1,"packet":[1]}]}`,
		`{"noise":[{"type":"exp","packet":"<r 1200><n>"}]}`,`{"noise":[{"type":"exp","packet":"x<b 00>"}]}`,
		`{"noise":[{"rand":1,"delay":1000},{"rand":1,"delay":1}]}`,`{"noise":[{"rand":1,"randRange":"2-1"}]}`,
	}{
		if _,err:=NewUDPChain(noiseOptions(s));err==nil{t.Fatalf("accepted %s",s)}
	}
}
func TestLXFinalMaskUDPNoiseInterrupt(t *testing.T){
	m,err:=NewUDPChain(noiseOptions(`{"noise":[{"packet":[1],"delay":1000}]}`))
	if err!=nil{t.Fatal(err)}
	for _,closeConn:=range []bool{true,false}{
		raw,peer:=net.Pipe()
		c:=m.WrapConnected(raw)
		done:=make(chan error,1)
		go func(){_,err:=c.Write([]byte("data"));done<-err}()
		peer.SetReadDeadline(time.Now().Add(time.Second))
		if _,err:=peer.Read(make([]byte,1));err!=nil{t.Fatal(err)}
		want:=error(os.ErrDeadlineExceeded)
		if closeConn{want=net.ErrClosed;c.Close()}else{c.SetWriteDeadline(time.Now().Add(-time.Millisecond))}
		select{
		case err:=<-done:if !errors.Is(err,want){t.Fatalf("got %v want %v",err,want)}
		case <-time.After(time.Second):t.Fatal("delay not interrupted")
		}
		c.Close();peer.Close()
	}
}

func TestLXFinalMaskUDPNoiseHalfOpenRanges(t *testing.T){
	m,err:=NewUDPChain(noiseOptions(`{"noise":[{"rand":"2-3","randRange":"9-9"},{"type":"exp","packet":"<r 3-4>"}]}`))
	if err!=nil{t.Fatal(err)}
	c:=m.WrapConnected(&capture{}).(*udpNoiseConn)
	for i:=0;i<100;i++{
		b,err:=c.packet(c.config.items[0])
		if err!=nil||!bytes.Equal(b,[]byte{9,9}){t.Fatalf("legacy range %x %v",b,err)}
		b,err=c.packet(c.config.items[1])
		if err!=nil||len(b)<3||len(b)>4{t.Fatalf("expression range %d %v",len(b),err)}
	}
}
