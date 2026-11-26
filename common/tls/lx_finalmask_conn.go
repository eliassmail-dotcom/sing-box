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
	lengths      []option.LXFinalMaskLengthRange
	minLength    int
	maxLo, maxHi int
	written      bool
}

func newLXFinalMaskConn(c net.Conn, o *option.LXFinalMaskFragmentOptions) net.Conn {
	lengths, _ := o.LengthRanges() // validated before config construction
	minLength := lengths[0].Min
	for _, length := range lengths[1:] {
		if length.Min < minLength {
			minLength = length.Min
		}
	}
	maxLo, maxHi, _ := o.MaxSplitBounds()
	return &lxFinalMaskConn{Conn: c, lengths: lengths, minLength: minLength, maxLo: maxLo, maxHi: maxHi}
}
func (c *lxFinalMaskConn) Write(p []byte) (int, error) {
	if len(p) == 0 || c.written {
		return c.Conn.Write(p)
	}
	c.written = true
	if len(p) < 9 || p[0] != 22 || p[5] != 1 {
		return c.Conn.Write(p)
	}
	n := int(binary.BigEndian.Uint16(p[3:5]))
	if n < 4 || n > 16384 || n+5 > len(p) {
		return c.Conn.Write(p)
	}
	data := p[5 : 5+n]
	maxRecords := c.maxLo
	if c.maxHi > c.maxLo {
		maxRecords += rand.Intn(c.maxHi - c.maxLo + 1)
	}
	recordCapacity := (n + c.minLength - 1) / c.minLength
	if maxRecords > 0 && recordCapacity > maxRecords {
		recordCapacity = maxRecords
	}
	out := make([]byte, 0, len(p)+5*recordCapacity)
	for index := 0; len(data) > 0; index++ {
		rangeIndex := index
		if rangeIndex >= len(c.lengths) {
			rangeIndex = len(c.lengths) - 1
		}
		length := c.lengths[rangeIndex]
		size := length.Min
		if length.Max > length.Min {
			size += rand.Intn(length.Max - length.Min + 1)
		}
		if size > len(data) || (maxRecords > 0 && index+1 >= maxRecords) {
			size = len(data)
		}
		out = append(out, p[:3]...)
		out = append(out, byte(size>>8), byte(size))
		out = append(out, data[:size]...)
		data = data[size:]
	}
	out = append(out, p[5+n:]...)
	wrote, err := c.Conn.Write(out)
	if err != nil {
		return 0, err
	}
	if wrote != len(out) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
func (c *lxFinalMaskConn) ReaderReplaceable() bool { return true }
func (c *lxFinalMaskConn) WriterReplaceable() bool { return c.written }
func (c *lxFinalMaskConn) Upstream() any           { return c.Conn }
