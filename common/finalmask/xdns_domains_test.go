package finalmask

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const multiDomainSettings = `{"domains":[{"names":["one.test","two.test"],"edns0":4096,"types":[16]},{"names":["longer.third.test"],"edns0":2048,"labelLimit":31,"lenLimit":180,"types":[5]}],"resolvers":[{"addrs":["udp://127.0.0.1:5353"]}]}`

func TestLXFinalMaskXDNSMultiDomain(t *testing.T){
	cfg,e:=compileXDNS(json.RawMessage(multiDomainSettings))
	if e!=nil{t.Fatal(e)}
	if len(cfg.domains)!=3||cfg.domains[0].domain!="one.test."||cfg.domains[1].domain!="two.test."||cfg.domains[2].domain!="longer.third.test."{t.Fatal("wrong domain list")}
	if cfg.domains[2].capacity>=cfg.domains[0].capacity||cfg.domains[2].labelLimit!=31||cfg.domains[2].edns!=2048{t.Fatal("independent domain limits lost")}
	peer,e:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if e!=nil{t.Fatal(e)}
	defer peer.Close()
	raw,e:=net.DialUDP("udp4",nil,peer.LocalAddr().(*net.UDPAddr))
	if e!=nil{t.Fatal(e)}
	c:=newXDNSConn(raw,cfg);defer c.Close()
	deadline:=time.Now().Add(3*time.Second)
	c.SetDeadline(deadline);peer.SetDeadline(deadline)
	c.ensure()
	type request struct{q dnsmessage.Message;addr *net.UDPAddr}
	get:=func()request{
		t.Helper()
		var b [512]byte
		n,a,e:=peer.ReadFromUDP(b[:]);if e!=nil{t.Fatal(e)}
		var q dnsmessage.Message
		if e=q.Unpack(b[:n]);e!=nil{t.Fatal(e)}
		return request{q,a}
	}
	// Force each codec independently to verify that an out-of-order
	// CNAME response uses the originating domain, not the first one.
	if e=c.sendDomain([]byte{1},cfg.domains[0]);e!=nil{t.Fatal(e)}
	first:=get()
	if e=c.sendDomain([]byte{2},cfg.domains[2]);e!=nil{t.Fatal(e)}
	second:=get()
	if first.q.Questions[0].Type!=dnsmessage.TypeTXT||second.q.Questions[0].Type!=dnsmessage.TypeCNAME||second.q.Additionals[0].Header.Class!=2048{t.Fatal("incorrect query settings")}
	reply:=func(r request,body dnsmessage.ResourceBody){
		t.Helper()
		q:=r.q
		q.Header.Response=true;q.Additionals=nil
		q.Answers=[]dnsmessage.Resource{{Header:dnsmessage.ResourceHeader{Name:q.Questions[0].Name,Type:q.Questions[0].Type,Class:dnsmessage.ClassINET},Body:body}}
		wire,e:=q.Pack();if e!=nil{t.Fatal(e)}
		if _,e=peer.WriteToUDP(wire,r.addr);e!=nil{t.Fatal(e)}
	}
	data:=binary.BigEndian.AppendUint16(nil,0xc003)
	data=append(data,7,8,9)
	record:=append([]byte{0,1},data...)
	wrong,e:=cfg.domains[0].name(record);if e!=nil{t.Fatal(e)}
	reply(second,&dnsmessage.CNAMEResource{CNAME:wrong})
	right,e:=cfg.domains[2].name(record);if e!=nil{t.Fatal(e)}
	reply(second,&dnsmessage.CNAMEResource{CNAME:right})
	var out [4096]byte
	n,e:=c.Read(out[:]);if e!=nil||!bytes.Equal(out[:n],[]byte{7,8,9}){t.Fatalf("CNAME response %d %v",n,e)}
	reply(first,&dnsmessage.TXTResource{TXT:[]string{string(data)}})
	n,e=c.Read(out[:]);if e!=nil||!bytes.Equal(out[:n],[]byte{7,8,9}){t.Fatalf("TXT response %d %v",n,e)}
	// Normal randomized send: all fragments must select the same domain,
	// EDNS and type, retain client identity, and reassemble correctly.
	p:=bytes.Repeat([]byte{4,5,6},401)
	if e=c.send(p);e!=nil{t.Fatal(e)}
	var selected *xdnsConfig
	var rebuilt []byte
	for i:=0;;i++{
		r:=get()
		q:=r.q.Questions[0]
		if selected==nil{
			for _,d:=range cfg.domains{if strings.HasSuffix(q.Name.String(),"."+d.domain){selected=d;break}}
			if selected==nil{t.Fatal("unknown selected domain")}
		}
		if q.Type!=selected.types[0]||r.q.Additionals[0].Header.Class!=dnsmessage.Class(selected.edns){t.Fatal("fragment settings changed")}
		frame,e:=selected.decodeName(q.Name)
		if e!=nil||len(frame)<15||frame[8]!=0xc3||int(frame[13])!=i||frame[12]!=1{t.Fatalf("invalid fragment %d %v",i,e)}
		if frame[0]&0xfc!=c.clientID[0]||!bytes.Equal(frame[1:8],c.clientID[1:]){t.Fatal("client identity changed")}
		rebuilt=append(rebuilt,frame[15:]...)
		if i+1==int(frame[14]){break}
	}
	if !bytes.Equal(rebuilt,p){t.Fatal("fragment reassembly mismatch")}
	if e=c.send(nil);e!=nil{t.Fatal(e)}
	_ = get()
	if c.frag!=1{t.Fatal("poll incremented fragment ID")}
}

func TestLXFinalMaskXDNSMultiDomainValidation(t *testing.T){
	for _,s:=range []string{
		strings.Replace(multiDomainSettings,"two.test","ONE.TEST",1),
		strings.Replace(multiDomainSettings,"two.test","sub.one.test",1),
		strings.Replace(multiDomainSettings,`"two.test"`,`"two.test","three.test","four.test"`,1),
		strings.Replace(multiDomainSettings,`["longer.third.test"]`,`[]`,1),
		strings.Replace(multiDomainSettings,`"edns0":2048`,`"edns0":512`,1),
		strings.Replace(multiDomainSettings,`"lenLimit":180`,`"lenLimit":20`,1),
	}{
		if _,e:=compileXDNS(json.RawMessage(s));e==nil{t.Fatal("invalid domain config accepted")}
	}
	cfg,e:=compileXDNS(json.RawMessage(xdnsTestConfig))
	if e!=nil||len(cfg.domains)!=0||cfg.domain!="unit.test."{t.Fatalf("single domain changed %v",e)}
}
