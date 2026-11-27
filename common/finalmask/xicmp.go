package finalmask

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const xicmpMaxPayload = 4080

type xicmpConfig struct {
	dgram bool
	ips []netip.Addr
}

func compileXICMP(raw json.RawMessage)(*xicmpConfig,error){
	var settings struct{
		DGRAM bool `json:"dgram"`
		IPs []string `json:"ips"`
	}
	if err:=decodeMaskSettings(raw,&settings);err!=nil{return nil,err}
	if len(settings.IPs)>4{return nil,errors.New("XICMP supports at most four endpoints")}
	c:=&xicmpConfig{dgram:settings.DGRAM}
	for _,s:=range settings.IPs{
		ip,err:=netip.ParseAddr(s)
		if err!=nil||!validXICMPIP(ip){return nil,errors.New("invalid XICMP endpoint")}
		ip=ip.Unmap()
		for _,prev:=range c.ips{if prev==ip{return nil,errors.New("duplicate XICMP endpoint")}}
		c.ips=append(c.ips,ip)
	}
	return c,nil
}
func validXICMPIP(ip netip.Addr)bool{
	return ip.IsValid()&&!ip.IsUnspecified()&&!ip.IsMulticast()&&ip.Zone()==""&&!ip.IsLinkLocalUnicast()&&ip.Unmap()!=netip.AddrFrom4([4]byte{255,255,255,255})
}

type xicmpListener interface{
	ListenXICMP(context.Context,netip.Addr,bool)(net.PacketConn,error)
}
func dialXICMP(ctx context.Context,dialer N.Dialer,server M.Socksaddr,cfg *xicmpConfig)(net.Conn,error){
	l,ok:=dialer.(xicmpListener)
	if !ok{return nil,errors.New("XICMP requires direct ICMP-capable dialer; detour unsupported")}
	ips:=cfg.ips
	if len(ips)==0{
		if !validXICMPIP(server.Addr){return nil,errors.New("XICMP requires literal server IP or explicit ips")}
		ips=[]netip.Addr{server.Addr.Unmap()}
	}
	var seed [2]byte
	if _,err:=rand.Read(seed[:]);err!=nil{return nil,err}
	first:=int(binary.BigEndian.Uint16(seed[:]))%len(ips)
	var errs []error
	for i:=range ips{
		if err:=ctx.Err();err!=nil{return nil,err}
		ip:=ips[(first+i)%len(ips)]
		pc,err:=l.ListenXICMP(ctx,ip,cfg.dgram)
		if err!=nil{errs=append(errs,err);continue}
		c,err:=newXICMPConn(pc,ip,cfg.dgram)
		if err!=nil{pc.Close();return nil,err}
		return c,nil
	}
	return nil,errors.Join(errs...)
}

type xicmpConn struct{
	net.PacketConn
	peer netip.Addr
	target net.Addr
	dgram bool
	clientID [8]byte
	id,seq uint16
	readMu,writeMu sync.Mutex
	rbuf [4097]byte
}
func newXICMPConn(raw net.PacketConn,ip netip.Addr,dgram bool)(*xicmpConn,error){
	c:=&xicmpConn{PacketConn:raw,peer:ip,dgram:dgram,seq:1}
	var seed [10]byte
	if _,err:=rand.Read(seed[:]);err!=nil{return nil,err}
	copy(c.clientID[:],seed[:8]);c.id=binary.BigEndian.Uint16(seed[8:])
	if dgram{c.target=&net.UDPAddr{IP:ip.AsSlice()}}else{c.target=&net.IPAddr{IP:ip.AsSlice()}}
	return c,nil
}
func(c *xicmpConn)RemoteAddr()net.Addr{return &net.UDPAddr{IP:c.peer.AsSlice()}}
func(c *xicmpConn)LocalAddr()net.Addr{
	a:=c.PacketConn.LocalAddr()
	if v,ok:=a.(*net.IPAddr);ok{return &net.UDPAddr{IP:v.IP,Zone:v.Zone}}
	return a
}
func(c *xicmpConn)Write(p []byte)(int,error){
	if len(p)==0||len(p)>xicmpMaxPayload{return 0,errors.New("invalid XICMP datagram size")}
	c.writeMu.Lock();defer c.writeMu.Unlock()
	typ:=icmp.Type(ipv4.ICMPTypeEcho)
	if c.peer.Is6(){typ=ipv6.ICMPTypeEchoRequest}
	data:=make([]byte,8+len(p))
	copy(data,c.clientID[:]);copy(data[8:],p)
	msg:=icmp.Message{Type:typ,Body:&icmp.Echo{ID:int(c.id),Seq:int(c.seq),Data:data}}
	c.seq++
	wire,err:=msg.Marshal(nil)
	if err!=nil{return 0,err}
	n,err:=c.PacketConn.WriteTo(wire,c.target)
	if err!=nil{return 0,err}
	if n!=len(wire){return 0,io.ErrShortWrite}
	return len(p),nil
}

func xicmpPeer(a net.Addr)netip.Addr{
	var ip net.IP
	switch v:=a.(type){case *net.IPAddr:ip=v.IP;case *net.UDPAddr:ip=v.IP;default:return netip.Addr{}}
	out,_:=netip.AddrFromSlice(ip)
	return out.Unmap()
}
func(c *xicmpConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock();defer c.readMu.Unlock()
	proto:=1
	reply:=icmp.Type(ipv4.ICMPTypeEchoReply)
	if c.peer.Is6(){proto=58;reply=ipv6.ICMPTypeEchoReply}
	for{
		n,addr,err:=c.PacketConn.ReadFrom(c.rbuf[:])
		if err!=nil{return 0,err}
		if n<9||n>4096||xicmpPeer(addr)!=c.peer{continue}
		m,err:=icmp.ParseMessage(proto,c.rbuf[:n])
		if err!=nil||m.Type!=reply||m.Code!=0{continue}
		e,ok:=m.Body.(*icmp.Echo)
		if !ok||(!c.dgram&&e.ID!=int(c.id))||len(e.Data)==0||len(e.Data)>xicmpMaxPayload{continue}
		if len(e.Data)>=8&&bytes.Equal(e.Data[:8],c.clientID[:]){continue}
		return copy(p,e.Data),nil
	}
}
func(c *xicmpConn)SetDeadline(t time.Time)error{return c.PacketConn.SetDeadline(t)}
