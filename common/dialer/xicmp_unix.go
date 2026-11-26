//go:build unix

package dialer

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"

	"github.com/sagernet/sing/common/metadata"
	"golang.org/x/sys/unix"
)

// ListenXICMP uses the same interface binding/protection/mark control as
// the existing direct ICMP path. No fallback to an unprotected socket.
func(d *DefaultDialer)ListenXICMP(ctx context.Context,destination netip.Addr,dgram bool)(net.PacketConn,error){
	if err:=ctx.Err();err!=nil{return nil,err}
	if d.netns!=""{return nil,errors.New("XICMP network namespace not supported")}
	if !destination.IsValid()||destination.IsUnspecified()||destination.Zone()!=""{return nil,errors.New("invalid XICMP destination")}
	ctl:=d.ICMPControl()
	ip:=netip.IPv4Unspecified()
	network:="ip4"
	rawNetwork:="ip4:icmp"
	family,proto:=unix.AF_INET,unix.IPPROTO_ICMP
	local:=d.udpDialer4.LocalAddr
	if destination.Is6(){ip=netip.IPv6Unspecified();network="ip6";rawNetwork="ip6:ipv6-icmp";family,proto=unix.AF_INET6,unix.IPPROTO_ICMPV6;local=d.udpDialer6.LocalAddr}
	if a,ok:=local.(*net.UDPAddr);ok{
		if a.Port!=0{return nil,errors.New("XICMP cannot use udp_bind_port")}
		if v,ok:=netip.AddrFromSlice(a.IP);ok{ip=v.Unmap()}
	}
	if !dgram{
		lc:=net.ListenConfig{}
		if ctl!=nil{
			lc.Control=func(_ string,_ string,raw syscall.RawConn)error{return ctl(network,destination.String(),raw)}
		}
		pc,err:=lc.ListenPacket(ctx,rawNetwork,ip.String())
		return d.trackPacketConn(ctx,metadata.SocksaddrFrom(destination,0),pc,err)
	}
	fd,err:=unix.Socket(family,unix.SOCK_DGRAM,proto)
	if err!=nil{return nil,err}
	unix.CloseOnExec(fd)
	file:=os.NewFile(uintptr(fd),"xicmp")
	defer file.Close()
	if ctl!=nil{
		raw,err:=file.SyscallConn();if err!=nil{return nil,err}
		if err=ctl(network,destination.String(),raw);err!=nil{return nil,err}
	}
	if err=unix.Bind(fd,metadata.AddrPortToSockaddr(netip.AddrPortFrom(ip,0)));err!=nil{return nil,err}
	pc,err:=net.FilePacketConn(file)
	if err!=nil{return nil,err}
	if err=ctx.Err();err!=nil{pc.Close();return nil,err}
	return d.trackPacketConn(ctx,metadata.SocksaddrFrom(destination,0),pc,nil)
}
