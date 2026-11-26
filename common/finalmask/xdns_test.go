package finalmask

import(
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
	"encoding/json"
	"strings"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)
const xdnsTestConfig=`{"domains":[{"names":["unit.test"],"edns0":4096}],"resolvers":[{"addrs":["udp://127.0.0.1:5353"]}]}`
func TestLXFinalMaskXDNSReference(t *testing.T){
	m,err:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{{Type:"xdns",Settings:json.RawMessage(xdnsTestConfig)}})
	if err!=nil{t.Fatal(err)}
	if !m.ReplacesCarrier()||m.DialDestination(M.ParseSocksaddr("192.0.2.1:443")).String()!="127.0.0.1:5353"{t.Fatal("resolver selection")}
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	defer peer.Close()
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{t.Fatal(err)}
	c:=m.WrapConnected(raw);defer c.Close()
	c.SetDeadline(time.Now().Add(2*time.Second));peer.SetDeadline(time.Now().Add(2*time.Second))
	payload:=bytes.Repeat([]byte{4,5,6},401)
	if n,err:=c.Write(payload);err!=nil||n!=len(payload){t.Fatalf("write %d %v",n,err)}
	var rebuilt []byte
	for i:=0;;i++{
		b:=make([]byte,512);n,addr,err:=peer.ReadFromUDP(b);if err!=nil{t.Fatal(err)}
		var q dnsmessage.Message
		if err=q.Unpack(b[:n]);err!=nil{t.Fatal(err)}
		name:=q.Questions[0].Name.String()
		s:=strings.ReplaceAll(strings.TrimSuffix(name,"unit.test."),".","")
		frame,err:=xdnsBase32.DecodeString(strings.ToUpper(s));if err!=nil{t.Fatal(err)}
		if frame[8]!=0xc3||int(frame[13])!=i{t.Fatalf("bad fragment %x",frame[:15])}
		rebuilt=append(rebuilt,frame[15:]...)
		if i+1!=int(frame[14]){continue}
		if !bytes.Equal(rebuilt,payload){t.Fatal("payload mismatch")}
		d:=binary.BigEndian.AppendUint16(nil,uint16(0xc000|len(payload)));d=append(d,payload...)
		var txt []string
		for len(d)>0{n:=min(len(d),255);txt=append(txt,string(d[:n]));d=d[n:]}
		q.Header.Response=true;q.Additionals=nil
		q.Answers=[]dnsmessage.Resource{{Header:dnsmessage.ResourceHeader{Name:q.Questions[0].Name,Type:dnsmessage.TypeTXT,Class:dnsmessage.ClassINET},Body:&dnsmessage.TXTResource{TXT:txt}}}
		wire,err:=q.Pack();if err!=nil{t.Fatal(err)}
		if _,err=peer.WriteToUDP(wire,addr);err!=nil{t.Fatal(err)}
		break
	}
	b:=make([]byte,4096)
	n,err:=c.Read(b)
	if err!=nil||!bytes.Equal(b[:n],payload){t.Fatalf("read %d %v",n,err)}
}
func TestLXFinalMaskXDNSValidation(t *testing.T){
	for _,s:=range []string{
		strings.Replace(xdnsTestConfig,"4096","512",1),
		strings.Replace(xdnsTestConfig,"udp://","tcp://",1),
		strings.Replace(xdnsTestConfig,"127.0.0.1","resolver.test",1),
		strings.Replace(xdnsTestConfig,"unit.test","unit..test",1),
		strings.Replace(xdnsTestConfig,"\"edns0\":4096","\"edns0\":4096,\"types\":[1]",1),
	}{
		if _,err:=compileXDNS(json.RawMessage(s));err==nil{t.Fatalf("accepted %s",s)}
	}
	var c *UDPChain
	addr:=M.ParseSocksaddr("127.0.0.1:443")
	if c.ReplacesCarrier()||c.DialDestination(addr)!=addr{t.Fatal("default changed")}
}
