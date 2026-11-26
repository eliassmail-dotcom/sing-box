package finalmask

import(
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/dns/dnsmessage"
)

func TestLXFinalMaskXDNSTCPFraming(t *testing.T){
	raw,peer:=net.Pipe()
	defer raw.Close();defer peer.Close()
	raw.SetDeadline(time.Now().Add(2*time.Second));peer.SetDeadline(time.Now().Add(2*time.Second))
	c:=newXDNSTCPConn(raw)
	done:=make(chan error,1)
	go func(){
		var b [5]byte
		_,err:=io.ReadFull(peer,b[:])
		if err==nil&&!bytes.Equal(b[:],[]byte{0,3,1,2,3}){err=io.ErrUnexpectedEOF}
		if err==nil{
			for _,p:=range [][]byte{{0},{2,4},{5,0,1,6}}{
				if _,err=peer.Write(p);err!=nil{break}
			}
		}
		done<-err
	}()
	if n,err:=c.Write([]byte{1,2,3});err!=nil||n!=3{t.Fatalf("write %d %v",n,err)}
	b:=make([]byte,4096)
	for _,want:=range [][]byte{{4,5},{6}}{
		n,err:=c.Read(b)
		if err!=nil||!bytes.Equal(b[:n],want){t.Fatalf("read %x %v",b[:n],err)}
	}
	if err:=<-done;err!=nil{t.Fatal(err)}
}

func TestLXFinalMaskXDNSTCPBadFrame(t *testing.T){
	for _,length:=range []uint16{0,4097}{
		raw,peer:=net.Pipe()
		c:=newXDNSTCPConn(raw)
		peer.SetDeadline(time.Now().Add(time.Second))
		go func(){peer.Write(binary.BigEndian.AppendUint16(nil,length))}()
		if _,err:=c.Read(make([]byte,4096));err==nil{t.Fatal("invalid length accepted")}
		if _,err:=peer.Write([]byte{1});err==nil{t.Fatal("corrupt stream remained open")}
		c.Close();peer.Close()
	}
}

func TestLXFinalMaskXDNSTCPExchange(t *testing.T){
	m,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{{Type:"xdns",Settings:json.RawMessage(strings.Replace(xdnsTestConfig,"udp://","tcp://",1))}})
	if err!=nil{t.Fatal(err)}
	if m.DialNetwork()!="tcp"||!m.ReplacesCarrier(){t.Fatal("incorrect carrier selection")}
	var absent *UDPChain
	if absent.DialNetwork()!="udp"{t.Fatal("default carrier changed")}
	listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil{t.Fatal(err)}
	defer listener.Close()
	raw,err:=net.Dial("tcp",listener.Addr().String());if err!=nil{t.Fatal(err)}
	peer,err:=listener.Accept();if err!=nil{raw.Close();t.Fatal(err)}
	defer peer.Close()
	c:=m.WrapConnected(raw);defer c.Close()
	if _,ok:=c.RemoteAddr().(*net.UDPAddr);!ok{t.Fatal("QUIC remote address not UDP")}
	c.SetDeadline(time.Now().Add(3*time.Second));peer.SetDeadline(time.Now().Add(3*time.Second))
	payload:=bytes.Repeat([]byte{4,5,6},401)
	done:=make(chan error,1)
	go func(){
		var rebuilt []byte
		for{
			var h [2]byte
			if _,e:=io.ReadFull(peer,h[:]);e!=nil{done<-e;return}
			b:=make([]byte,int(binary.BigEndian.Uint16(h[:])))
			if _,e:=io.ReadFull(peer,b);e!=nil{done<-e;return}
			var q dnsmessage.Message
			if e:=q.Unpack(b);e!=nil{done<-e;return}
			s:=strings.ReplaceAll(strings.TrimSuffix(q.Questions[0].Name.String(),"unit.test."),".","")
			frame,e:=xdnsBase32.DecodeString(strings.ToUpper(s))
			if e!=nil||len(frame)<15||frame[8]!=0xc3{done<-io.ErrUnexpectedEOF;return}
			rebuilt=append(rebuilt,frame[15:]...)
			if frame[13]+1!=frame[14]{continue}
			if !bytes.Equal(rebuilt,payload){done<-io.ErrUnexpectedEOF;return}
			d:=binary.BigEndian.AppendUint16(nil,uint16(0xc000|len(payload)));d=append(d,payload...)
			var txt []string
			for len(d)>0{n:=min(len(d),255);txt=append(txt,string(d[:n]));d=d[n:]}
			q.Header.Response=true;q.Additionals=nil
			q.Answers=[]dnsmessage.Resource{{Header:dnsmessage.ResourceHeader{Name:q.Questions[0].Name,Type:dnsmessage.TypeTXT,Class:dnsmessage.ClassINET},Body:&dnsmessage.TXTResource{TXT:txt}}}
			wire,e:=q.Pack();if e!=nil{done<-e;return}
			_,e=peer.Write(append(binary.BigEndian.AppendUint16(nil,uint16(len(wire))),wire...));done<-e;return
		}
	}()
	if n,e:=c.Write(payload);e!=nil||n!=len(payload){t.Fatalf("write %d %v",n,e)}
	b:=make([]byte,4096)
	if n,e:=c.Read(b);e!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("read %d %v",n,e)}
	if e:=<-done;e!=nil{t.Fatal(e)}
}
