package finalmask

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

const xdnsTCPFrameLimit = 4096

// DNS-over-TCP uses a two-byte big-endian message length (RFC 1035).
// Adapt the stream to the existing XDNS datagram reader/writer without
// adding more workers. Any partial frame or framing error closes the
// stream: continuing after a partial write could desynchronize it.
type xdnsTCPConn struct {
	net.Conn
	readMu,writeMu sync.Mutex
	writeBuf [xdnsTCPFrameLimit+2]byte
}

func newXDNSTCPConn(raw net.Conn)net.Conn{return &xdnsTCPConn{Conn:raw}}

func(c *xdnsTCPConn)Write(p []byte)(int,error){
	if len(p)==0||len(p)>xdnsTCPFrameLimit{return 0,errors.New("invalid XDNS TCP message size")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire:=c.writeBuf[:len(p)+2]
	binary.BigEndian.PutUint16(wire,uint16(len(p)))
	copy(wire[2:],p)
	for len(wire)>0{
		n,err:=c.Conn.Write(wire)
		if err!=nil{_ = c.Conn.Close();return 0,err}
		if n<=0||n>len(wire){_ = c.Conn.Close();return 0,io.ErrShortWrite}
		wire=wire[n:]
	}
	return len(p),nil
}

func(c *xdnsTCPConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var prefix [2]byte
	if _,err:=io.ReadFull(c.Conn,prefix[:]);err!=nil{_ = c.Conn.Close();return 0,err}
	n:=int(binary.BigEndian.Uint16(prefix[:]))
	if n==0||n>xdnsTCPFrameLimit||n>len(p){
		_ = c.Conn.Close()
		return 0,errors.New("invalid XDNS TCP response size")
	}
	if _,err:=io.ReadFull(c.Conn,p[:n]);err!=nil{_ = c.Conn.Close();return 0,err}
	return n,nil
}

// QUIC sees a datagram endpoint even though its carrier is a TCP stream.
// Preserve the actual address values, but expose UDP address semantics.
func xdnsUDPAddr(a net.Addr)net.Addr{
	if t,ok:=a.(*net.TCPAddr);ok{return &net.UDPAddr{IP:t.IP,Port:t.Port,Zone:t.Zone}}
	return a
}
func(c *xdnsTCPConn)LocalAddr()net.Addr{return xdnsUDPAddr(c.Conn.LocalAddr())}
func(c *xdnsTCPConn)RemoteAddr()net.Addr{return xdnsUDPAddr(c.Conn.RemoteAddr())}
