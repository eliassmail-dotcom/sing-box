package finalmask

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/dns/dnsmessage"
)

const xdnsMaxPayload=4096

var xdnsBase32=base32.StdEncoding.WithPadding(base32.NoPadding)

type xdnsConfig struct{
	resolver M.Socksaddr
	alternates []*xdnsConfig
	network string
	dohURL, dohServerName string
	dohWorkers int
	dohALPN []string
	dohH3 bool
	dohH3Settings *xdnsH3Settings
	domain string
	types []dnsmessage.Type
	labelLimit,capacity,edns,extraPoll int
}

type xdnsSettings struct{
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
			BootstrapIP string `json:"bootstrapIP"`
			QUIC *option.LXFinalMaskQUICParams `json:"quicConfig"`
			TLS *struct{
				ServerName string `json:"serverName"`
				ALPN []string `json:"alpn"`
				AllowInsecure bool `json:"allowInsecure"`
			} `json:"tlsConfig"`
		} `json:"resolvers"`
		ExtraPoll int `json:"extraPoll"`
	}

func compileXDNS(raw json.RawMessage)(*xdnsConfig,error){
	var s xdnsSettings
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if len(s.Domains)!=1||len(s.Domains[0].Names)!=1||len(s.Resolvers)==0||len(s.Resolvers)>3{return nil,errors.New("XDNS requires one domain and one to three resolvers")}
	var entries []*xdnsConfig
	workers:=0
	seenResolvers:=make(map[string]bool)
	for i,r:=range s.Resolvers{
		if len(r.Addrs)==0||len(r.Addrs)>3{return nil,errors.New("invalid XDNS resolver address count")}
		for _,addr:=range r.Addrs{
			if len(entries)>=3{return nil,errors.New("XDNS supports at most three resolver addresses")}
			single:=s
			single.Resolvers=append(s.Resolvers[:0:0],s.Resolvers[i])
			single.Resolvers[0].Addrs=[]string{addr}
			cfg,err:=compileXDNSSingle(single)
			if err!=nil{return nil,err}
			key:=cfg.network+"|"+cfg.resolver.String()+"|"+cfg.dohURL
			if seenResolvers[key]{return nil,errors.New("duplicate XDNS resolver")}
			seenResolvers[key]=true
			workers+=cfg.dohWorkers
			if workers>4{return nil,errors.New("XDNS aggregate DoH worker budget exceeds four")}
			entries=append(entries,cfg)
		}
	}
	primary:=entries[0]
	primary.alternates=entries[1:]
	return primary,nil
}

func compileXDNSSingle(s xdnsSettings)(*xdnsConfig,error){
	d,r:=s.Domains[0],s.Resolvers[0]
	if len(d.Types)==0{d.Types=[]int{16}}
	if len(d.Types)>4{return nil,errors.New("too many XDNS query types")}
	var types []dnsmessage.Type
	seen:=make(map[int]bool)
	for _,v:=range d.Types{
		switch v{case 1,5,16,28:default:return nil,errors.New("unsupported XDNS query type")}
		if seen[v]{return nil,errors.New("duplicate XDNS query type")}
		seen[v]=true
		types=append(types,dnsmessage.Type(v))
	}
	if d.EDNS<2048||d.EDNS>4096{return nil,errors.New("XDNS QUIC pilot requires edns0 2048-4096")}
	if r.Worker<0||r.Worker>32||s.ExtraPoll<0||s.ExtraPoll>3{return nil,errors.New("invalid XDNS worker or extraPoll")}
	address:=r.Addrs[0]
	if !strings.Contains(address,"://"){address="udp://"+address}
	u,err:=url.Parse(address)
	if err!=nil||u.User!=nil||u.Fragment!=""||u.Hostname()==""{return nil,errors.New("invalid XDNS resolver address")}
	if u.Scheme!="udp"&&u.Scheme!="tcp"&&u.Scheme!="https"{return nil,errors.New("unsupported XDNS resolver scheme")}
	if u.Scheme!="https"&&(u.Path!=""||u.RawQuery!=""||r.TLS!=nil||r.QUIC!=nil||r.BootstrapIP!=""){return nil,errors.New("invalid plain XDNS resolver options")}
	if u.Scheme=="https"&&(u.Path==""||u.RawQuery!=""){return nil,errors.New("XDNS DoH requires explicit HTTPS path without query")}
	if r.TLS!=nil&&r.TLS.AllowInsecure{return nil,errors.New("XDNS DoH requires TLS verification")}
	host:=u.Hostname()
	ip,err:=netip.ParseAddr(host)
	if err!=nil{
		if u.Scheme!="https"||r.BootstrapIP==""||!validXDNSResolverHost(host){return nil,errors.New("XDNS hostname requires HTTPS and explicit bootstrapIP")}
		ip,err=netip.ParseAddr(r.BootstrapIP)
	}else if r.BootstrapIP!=""{return nil,errors.New("bootstrapIP requires a resolver hostname")}
	if err!=nil||!validXICMPIP(ip){return nil,errors.New("invalid XDNS resolver IP")}
	ip=ip.Unmap()
	port:=u.Port()
	if port==""{port="53";if u.Scheme=="https"{port="443"}}
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
	cfg:=&xdnsConfig{resolver:M.ParseSocksaddr(net.JoinHostPort(ip.String(),port)),network:u.Scheme,domain:domain,types:types,labelLimit:d.LabelLimit,capacity:capacity,edns:d.EDNS,extraPoll:s.ExtraPoll}
	if u.Scheme=="https"{
		cfg.dohURL=u.String();cfg.dohWorkers=r.Worker
		cfg.dohServerName=host
		if cfg.dohWorkers==0{cfg.dohWorkers=4}
		if cfg.dohWorkers>4{return nil,errors.New("XDNS DoH supports at most four workers")}
		if r.TLS!=nil{
			if r.TLS.ServerName!=""{cfg.dohServerName=r.TLS.ServerName};cfg.dohALPN=r.TLS.ALPN
			if len(cfg.dohALPN)>2{return nil,errors.New("invalid XDNS DoH ALPN")}
			for _,v:=range cfg.dohALPN{
				if v=="h3"{
					if len(cfg.dohALPN)!=1||!xdnsDoH3Available{return nil,errors.New("XDNS DoH h3 requires exclusive h3 ALPN and with_quic build")}
					cfg.dohH3=true
				}else if v!="h2"&&v!="http/1.1"{return nil,errors.New("invalid XDNS DoH ALPN")}
			}
		}
	}
	if r.QUIC!=nil&&!cfg.dohH3{return nil,errors.New("XDNS quicConfig requires HTTP/3")}
	if cfg.dohH3{
		cfg.dohH3Settings,err=compileXDNSH3Params(r.QUIC)
		if err!=nil{return nil,err}
	}
	return cfg,nil
}

func validXDNSResolverHost(host string)bool{
	if len(host)==0||len(host)>253||strings.HasSuffix(host,"."){return false}
	for _,l:=range strings.Split(strings.ToLower(host),"."){
		if len(l)==0||len(l)>63||l[0]=='-'||l[len(l)-1]=='-'{return false}
		for _,b:=range []byte(l){if !(b>='a'&&b<='z'||b>='0'&&b<='9'||b=='-'){return false}}
	}
	return true
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
		Questions:[]dnsmessage.Question{{Name:name,Type:xdnsQueryType(data[0]&3),Class:dnsmessage.ClassINET}},
		Additionals:[]dnsmessage.Resource{{Header:dnsmessage.ResourceHeader{Name:dnsmessage.MustNewName("."),Type:dnsmessage.TypeOPT,Class:dnsmessage.Class(c.edns)},Body:&dnsmessage.OPTResource{}}},
	}
	wire,err:=msg.Pack()
	return wire,name.String(),err
}

// Mirrors the upstream 8-byte ID and 3-byte random data nonce, with
// fragment ID/index/count for packets exceeding the domain capacity.
func(c *xdnsConfig)frames(id [8]byte,frag byte,p []byte)([][]byte,error){
	if len(p)>xdnsMaxPayload{return nil,errors.New("XDNS datagram too large")}
	id[0]=(id[0]&0xfc)|xdnsTypeBits(c.types[mathrand.Intn(len(c.types))])
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

// The low two bits of the client ID carry the query type.
func xdnsQueryType(bits byte)dnsmessage.Type{
	return [...]dnsmessage.Type{dnsmessage.TypeA,dnsmessage.TypeCNAME,dnsmessage.TypeTXT,dnsmessage.TypeAAAA}[bits&3]
}
func xdnsTypeBits(t dnsmessage.Type)byte{
	switch t{case dnsmessage.TypeA:return 0;case dnsmessage.TypeCNAME:return 1;case dnsmessage.TypeAAAA:return 3;default:return 2}
}

func(c *xdnsConfig)decodeName(name dnsmessage.Name)([]byte,error){
	s:=strings.ToLower(name.String())
	suffix:="."+c.domain
	if !strings.HasSuffix(s,suffix){return nil,errors.New("XDNS CNAME domain mismatch")}
	s=strings.TrimSuffix(s,suffix)
	var encoded strings.Builder
	for _,label:=range strings.Split(s,"."){
		if len(label)==0||len(label)>c.labelLimit{return nil,errors.New("invalid XDNS CNAME label")}
		encoded.WriteString(label)
	}
	if encoded.Len()>xdnsBase32.EncodedLen(c.capacity){return nil,errors.New("XDNS CNAME exceeds capacity")}
	b,err:=xdnsBase32.DecodeString(strings.ToUpper(encoded.String()))
	if err!=nil||len(b)>c.capacity{return nil,errors.New("invalid XDNS CNAME data")}
	return b,nil
}

func(c *xdnsConfig)decodeResponse(msg *dnsmessage.Message,expected string,typ dnsmessage.Type)([][]byte,error){
	if !msg.Header.Response||msg.Header.Truncated||msg.Header.RCode!=dnsmessage.RCodeSuccess||len(msg.Questions)!=1{return nil,errors.New("invalid XDNS response")}
	q:=msg.Questions[0]
	if q.Type!=typ||q.Class!=dnsmessage.ClassINET||!strings.EqualFold(q.Name.String(),expected){return nil,errors.New("XDNS question mismatch")}
	if len(msg.Answers)==0{return nil,nil}
	var data []byte
	padding:=0
	validHeader:=func(a dnsmessage.Resource)bool{return a.Header.Type==typ&&a.Header.Class==dnsmessage.ClassINET&&strings.EqualFold(a.Header.Name.String(),expected)}
	if typ==dnsmessage.TypeTXT{
		if len(msg.Answers)!=1||!validHeader(msg.Answers[0]){return nil,errors.New("invalid XDNS TXT answer")}
		txt,ok:=msg.Answers[0].Body.(*dnsmessage.TXTResource)
		if !ok{return nil,errors.New("invalid XDNS TXT body")}
		for _,s:=range txt.TXT{
			if len(data)+len(s)>xdnsMaxPayload{return nil,errors.New("XDNS response payload exceeds budget")}
			data=append(data,s...)
		}
	}else{
		// A/AAAA and CNAME use indexed records; recursive resolvers may
		// reorder them. Require complete, contiguous, non-duplicate indices.
		if len(msg.Answers)>255{return nil,errors.New("too many XDNS response records")}
		var parts [255][]byte
		count:=0
		for _,a:=range msg.Answers{
			if !validHeader(a){return nil,errors.New("XDNS answer mismatch")}
			var b []byte
			switch typ{
			case dnsmessage.TypeA:
				r,ok:=a.Body.(*dnsmessage.AResource);if !ok{return nil,errors.New("invalid A body")};b=r.A[:];padding=2
			case dnsmessage.TypeAAAA:
				r,ok:=a.Body.(*dnsmessage.AAAAResource);if !ok{return nil,errors.New("invalid AAAA body")};b=r.AAAA[:];padding=14
			case dnsmessage.TypeCNAME:
				r,ok:=a.Body.(*dnsmessage.CNAMEResource);if !ok{return nil,errors.New("invalid CNAME body")}
				var err error;b,err=c.decodeName(r.CNAME);if err!=nil{return nil,err}
			default:return nil,errors.New("invalid XDNS response type")
			}
			if len(b)<2||int(b[0])>=len(parts)||parts[b[0]]!=nil{return nil,errors.New("invalid XDNS response index")}
			parts[b[0]]=b
			if b[0]==0{count=int(b[1]);if len(b)<3{return nil,errors.New("empty XDNS first record")}}
		}
		if count==0||count!=len(msg.Answers){return nil,errors.New("incomplete XDNS response records")}
		for i:=0;i<count;i++{
			b:=parts[i];if b==nil{return nil,errors.New("missing XDNS record")}
			skip:=1;if i==0{skip=2}
			if len(data)+len(b)-skip>xdnsMaxPayload+padding{return nil,errors.New("XDNS response payload exceeds budget")}
			data=append(data,b[skip:]...)
		}
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
			if len(data)>padding{return nil,errors.New("trailing XDNS response bytes")}
			for _,b:=range data{if b!=0{return nil,errors.New("nonzero XDNS response padding")}}
			return packets,nil
		}
		if v&0xc000!=0{return nil,errors.New("invalid XDNS response flags")}
	}
	return nil,fmt.Errorf("missing XDNS final frame")
}
