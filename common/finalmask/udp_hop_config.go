package finalmask

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type udpHopConfig struct{
	local,remote,once bool
	min,max int
	prefixes []netip.Prefix
	ports []uint16
}
func compileUDPHop(raw json.RawMessage)(*udpHopConfig,error){
	var s struct{
		Mode string `json:"mode"`
		Interval json.RawMessage `json:"interval"`
		RemoteIPs []string `json:"remoteIPs"`
		RemotePorts json.RawMessage `json:"remotePorts"`
	}
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	c:=&udpHopConfig{}
	for _,mode:=range strings.Split(strings.ToLower(s.Mode),","){
		switch mode{
		case "intervallocal":if c.local{return nil,errors.New("duplicate UDP Hop mode")};c.local=true
		case "intervalremote":if c.remote{return nil,errors.New("duplicate UDP Hop mode")};c.remote=true
		case "perconnremote":if c.once{return nil,errors.New("duplicate UDP Hop mode")};c.once=true
		default:return nil,errors.New("invalid UDP Hop mode")
		}
	}
	lo,hi,err:=headerRange(s.Interval,30,5,3600)
	if err!=nil{return nil,err}
	c.min,c.max=lo,hi
	if len(s.RemoteIPs)>8{return nil,errors.New("too many UDP Hop prefixes")}
	for _,v:=range s.RemoteIPs{
		p,e:=netip.ParsePrefix(v)
		if e!=nil{a,e:=netip.ParseAddr(v);if e!=nil{return nil,errors.New("invalid UDP Hop IP")};p=netip.PrefixFrom(a,a.BitLen())}
		p=p.Masked()
		if p.Addr().Is4In6()||!validXICMPIP(p.Addr())||p.Addr().BitLen()-p.Bits()>8{return nil,errors.New("UDP Hop requires bounded unicast prefix")}
		c.prefixes=append(c.prefixes,p)
	}
	if len(s.RemotePorts)>0&&string(s.RemotePorts)!="null"{
		var str string
		if json.Unmarshal(s.RemotePorts,&str)!=nil{var n int;if json.Unmarshal(s.RemotePorts,&n)!=nil{return nil,errors.New("invalid UDP Hop ports")};str=strconv.Itoa(n)}
		seen:=make(map[uint16]bool)
		for _,part:=range strings.Split(str,","){
			a,b,rangeOK:=strings.Cut(strings.TrimSpace(part),"-")
			if !rangeOK{b=a}
			lo,e:=strconv.Atoi(a);hi,e2:=strconv.Atoi(b)
			if e!=nil||e2!=nil||lo<1||hi>65535||lo>hi||hi-lo>=256{return nil,errors.New("invalid UDP Hop port range")}
			for p:=lo;p<=hi;p++{v:=uint16(p);if !seen[v]{if len(c.ports)>=256{return nil,errors.New("too many UDP Hop ports")};seen[v]=true;c.ports=append(c.ports,v)}}
		}
	}
	if (c.remote||c.once)&&len(c.prefixes)==0&&len(c.ports)==0{return nil,errors.New("UDP Hop remote mode needs remoteIPs or remotePorts")}
	if !c.remote&&!c.once&&(len(c.prefixes)>0||len(c.ports)>0){return nil,errors.New("unused UDP Hop remote settings")}
	return c,nil
}
func(c *udpHopConfig)interval()time.Duration{return time.Duration(c.min+rand.Intn(c.max-c.min+1))*time.Second}
func(c *udpHopConfig)target(base M.Socksaddr)M.Socksaddr{
	if len(c.prefixes)>0{
		p:=c.prefixes[rand.Intn(len(c.prefixes))]
		b:=p.Addr().AsSlice()
		bits:=p.Addr().BitLen()-p.Bits()
		if bits>0{b[len(b)-1]|=byte(rand.Intn(1<<bits))}
		a,_:=netip.AddrFromSlice(b)
		if validXICMPIP(a){base.Addr=a;base.Fqdn=""}
	}
	if len(c.ports)>0{base.Port=c.ports[rand.Intn(len(c.ports))]}
	return base
}
func(c *udpHopConfig)validateServer(server M.Socksaddr)error{
	if !validXICMPIP(server.Addr)||server.Port==0||server.IsDomain(){return errors.New("UDP Hop requires literal server IP and port")}
	for _,p:=range c.prefixes{if p.Addr().Is4()!=server.Addr.Is4(){return errors.New("UDP Hop mixed address families unsupported")}}
	return nil
}
func hopUDPAddr(a M.Socksaddr)net.Addr{return a.UDPAddr()}
func hopSameAddr(a net.Addr,b M.Socksaddr)bool{return M.SocksaddrFromNet(a).Unwrap().AddrPort()==b.Unwrap().AddrPort()}
