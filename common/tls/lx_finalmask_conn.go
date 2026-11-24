package tls

import (
    "encoding/binary"
    "io"
    "math/rand"
    "net"
    "github.com/sagernet/sing-box/option"
)

// Only the first complete ClientHello record is transformed. The handshake
// payload and any following records remain byte-for-byte intact.
type lxFinalMaskConn struct {
    net.Conn
    lo, hi int
    written bool
}
func newLXFinalMaskConn(c net.Conn, o *option.LXFinalMaskFragmentOptions) net.Conn {
    lo,hi,_ := o.Bounds() // validated before config construction
    return &lxFinalMaskConn{Conn:c,lo:lo,hi:hi}
}
func (c *lxFinalMaskConn) Write(p []byte) (int,error) {
    if len(p)==0 || c.written { return c.Conn.Write(p) }
    c.written=true
    if len(p)<9 || p[0]!=22 || p[5]!=1 { return c.Conn.Write(p) }
    n:=int(binary.BigEndian.Uint16(p[3:5]))
    if n<4 || n>16384 || n+5>len(p) { return c.Conn.Write(p) }
    data:=p[5:5+n]
    out:=make([]byte,0,len(p)+5*((n+c.lo-1)/c.lo))
    for len(data)>0 {
        size:=c.lo
        if c.hi>c.lo { size+=rand.Intn(c.hi-c.lo+1) }
        if size>len(data) { size=len(data) }
        out=append(out,p[:3]...)
        out=append(out,byte(size>>8),byte(size))
        out=append(out,data[:size]...)
        data=data[size:]
    }
    out=append(out,p[5+n:]...)
    wrote,err:=c.Conn.Write(out)
    if err!=nil { return 0,err }
    if wrote!=len(out) { return 0,io.ErrShortWrite }
    return len(p),nil
}
func(c *lxFinalMaskConn) ReaderReplaceable() bool { return true }
func(c *lxFinalMaskConn) WriterReplaceable() bool { return c.written }
func(c *lxFinalMaskConn) Upstream() any { return c.Conn }
