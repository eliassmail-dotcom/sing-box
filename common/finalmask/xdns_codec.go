package finalmask

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

const xdnsMaxPayload=4096

var xdnsBase32=base32.StdEncoding.WithPadding(base32.NoPadding)

type xdnsConfig struct{
	resolver M.Socksaddr
	domain string
	labelLimit,capacity,edns,extraPoll int
}

func compileXDNS(raw json.RawMessage)(*xdnsConfig,error){
	var s struct{
		Domains []struct{
			Names []string `json:"names"`
			LenLimit int `json:"lenLimit"`
			LabelLimit int `json:"labelLimit"`
			Types []int `json:"types"`
			EDNS int `json:"edns0"`
		} `json:"domains"`
		Resolvers []struct{
			Addrs []string `json:"addrs"`
			Worker int `json:"worker"`
		} `json:"resolvers"`
		ExtraPoll int `json:"extraPoll"`
	}
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if len(s.Domains)!=1||len(s.Domains[0].Names)!=1||len(s.Resolvers)!=1||len(s.Resolvers[0].Addrs)!=1{return nil,errors.New("XDNS pilot requires one domain and one UDP resolver")}
	d,r:=s.Domains[0],s.Resolvers[0]
	if len(d.Types)>1||(len(d.Types)==1&&d.Types[0]!=16){return nil,errors.New("XDNS pilot supports TXT only")}
	if d.EDNS<2048||d.EDNS>4096{return nil,errors.New("XDNS QUIC pilot requires edns0 2048-4096")}
	if r.Worker<0||r.Worker>32||s.ExtraPoll<0||s.ExtraPoll>3{return nil,errors.New("invalid XDNS worker or extraPoll")}
	address:=r.Addrs[0]
	if !strings.Contains(address,"://"){address="udp://"+address}
	u,err:=url.Parse(address)
	if err!=nil||u.Scheme!="udp"||u.User!=nil||u.Path!=""||u.RawQuery!=""||u.Fragment!=""{return nil,errors.New("XDNS requires a UDP resolver address")}
	ip,err:=netip.ParseAddr(u.Hostname())
	if err!=nil||ip.Zone()!=""||ip.IsUnspecified(){return nil,errors.New("XDNS pilot requires a literal resolver IP")}
	port:=u.Port()
	if port==""{port="53"}
	p,err:=strconv.Atoi(port)
	if err!=nil||p<1||p>65535{return nil,errors.New("invalid XDNS resolver port")}
	domain:=strings.ToLower(d.Names[0])
	if domain==""||len(domain)>253||strings.HasSuffix(domain,"."){return nil,errors.New("invalid XDNS domain")}
	for _,label:=range strings.Split(domain,"."){
		if len(label)==0||len(label)>63{return nil,errors.New("invalid XDNS domain label")}
		for _,b:=range []byte(label){if !(b>='a'&&b<='z'||b>='0'&&b<='9'||b=='-'){return nil,errors.New("XDNS pilot requires ASCII DNS labels")}}
	}
	domain+="."
	if d.LenLimit==0{d.LenLimit=255}
	if d.LabelLimit==0{d.LabelLimit=63}
	if d.LenLimit<1||d.LenLimit>255||d.LabelLimit<1||d.LabelLimit>63{return nil,errors.New("invalid XDNS name limits")}
	capacity:=0
	for n:=1;n<=159;n++{
		enc:=xdnsBase32.EncodedLen(n)
		labels:=(enc+d.LabelLimit-1)/d.LabelLimit
		if len(domain)+enc+labels+1>d.LenLimit{break}
		capacity=n
	}
	if capacity<32{return nil,errors.New("XDNS domain capacity too small")}
	return &xdnsConfig{resolver:M.ParseSocksaddr(net.JoinHostPort(ip.String(),port)),domain:domain,labelLimit:d.LabelLimit,capacity:capacity,edns:d.EDNS,extraPoll:s.ExtraPoll},nil
}

func(c *xdnsConfig)name(data []byte)(dnsmessage.Name,error){
	if len(data)>c.capacity{return dnsmessage.Name{},errors.New("XDNS query exceeds name capacity")}
	s:=strings.ToLower(xdnsBase32.EncodeToString(data))
	var b strings.Builder
	for len(s)>0{n:=min(len(s),c.labelLimit);b.WriteString(s[:n]);b.WriteByte('.');s=s[n:]}
	b.WriteString(c.domain)
	return dnsmessage.NewName(b.String())
}
func(c *xdnsConfig)query(id uint16,data []byte)([]byte,string,error){
	name,err:=c.name(data)
	if err!=nil{return nil,"",err}
	msg:=dnsmessage.Message{
		Header:dnsmessage.Header{ID:id,RecursionDesired:true},
		Questions:[]dnsmessage.Question{{Name:name,Type:dnsmessage.TypeTXT,Class:dnsmessage.ClassINET}},
		Additionals:[]dnsmessage.Resource{{Header:dnsmessage.ResourceHeader{Name:dnsmessage.MustNewName("."),Type:dnsmessage.TypeOPT,Class:dnsmessage.Class(c.edns)},Body:&dnsmessage.OPTResource{}}},
	}
	wire,err:=msg.Pack()
	return wire,name.String(),err
}

// Mirrors the upstream 8-byte ID and 3-byte random data nonce, with
// fragment ID/index/count for packets exceeding the domain capacity.
func(c *xdnsConfig)frames(id [8]byte,frag byte,p []byte)([][]byte,error){
	if len(p)>xdnsMaxPayload{return nil,errors.New("XDNS datagram too large")}
	id[0]=(id[0]&0xfc)|2
	if len(p)==0{
		b:=make([]byte,17);copy(b,id[:]);b[8]=8
		if _,err:=rand.Read(b[9:]);err!=nil{return nil,err}
		return [][]byte{b},nil
	}
	if len(p)<=c.capacity-12{
		b:=make([]byte,12+len(p));copy(b,id[:]);b[8]=3
		if _,err:=rand.Read(b[9:12]);err!=nil{return nil,err}
		copy(b[12:],p)
		return [][]byte{b},nil
	}
	chunk:=c.capacity-15
	count:=(len(p)+chunk-1)/chunk
	if count>255{return nil,errors.New("too many XDNS fragments")}
	var nonce [3]byte
	if _,err:=rand.Read(nonce[:]);err!=nil{return nil,err}
	out:=make([][]byte,0,count)
	for i:=0;i<count;i++{
		n:=min(chunk,len(p));b:=make([]byte,15+n)
		copy(b,id[:]);b[8]=0xc3;copy(b[9:12],nonce[:])
		b[12],b[13],b[14]=frag,byte(i),byte(count)
		copy(b[15:],p[:n]);p=p[n:]
		out=append(out,b)
	}
	return out,nil
}

func decodeXDNSResponse(msg *dnsmessage.Message,expected string)([][]byte,error){
	if !msg.Header.Response||msg.Header.Truncated||msg.Header.RCode!=dnsmessage.RCodeSuccess||len(msg.Questions)!=1{return nil,errors.New("invalid XDNS response")}
	q:=msg.Questions[0]
	if q.Type!=dnsmessage.TypeTXT||q.Class!=dnsmessage.ClassINET||!strings.EqualFold(q.Name.String(),expected){return nil,errors.New("XDNS question mismatch")}
	if len(msg.Answers)==0{return nil,nil}
	if len(msg.Answers)!=1{return nil,errors.New("invalid XDNS TXT answer count")}
	a:=msg.Answers[0]
	if a.Header.Type!=dnsmessage.TypeTXT||a.Header.Class!=dnsmessage.ClassINET||!strings.EqualFold(a.Header.Name.String(),expected){return nil,errors.New("XDNS TXT answer mismatch")}
	txt,ok:=a.Body.(*dnsmessage.TXTResource)
	if !ok{return nil,errors.New("invalid XDNS TXT body")}
	var data []byte
	for _,s:=range txt.TXT{
		if len(data)+len(s)>xdnsMaxPayload{return nil,errors.New("XDNS response payload exceeds budget")}
		data=append(data,s...)
	}
	if len(data)==0{return nil,nil}
	var packets [][]byte
	for len(data)>=2{
		v:=binary.BigEndian.Uint16(data)
		n:=int(v&0x3fff)
		data=data[2:]
		if n==0||n>len(data)||len(packets)>=16{return nil,errors.New("invalid XDNS response frame")}
		packets=append(packets,bytes.Clone(data[:n]))
		data=data[n:]
		if v&0xc000==0xc000{
			if len(data)!=0{return nil,errors.New("trailing XDNS response bytes")}
			return packets,nil
		}
		if v&0xc000!=0{return nil,errors.New("invalid XDNS response flags")}
	}
	return nil,fmt.Errorf("missing XDNS final frame")
}
