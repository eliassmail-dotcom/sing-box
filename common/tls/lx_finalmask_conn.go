package tls

import (
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/option"
)

// Only the first complete ClientHello record is transformed. The handshake
// payload and any following records remain byte-for-byte intact.
type lxFinalMaskConn struct {
	net.Conn
	lengths      []option.LXFinalMaskLengthRange
	minLength    int
	maxLo, maxHi int
	delays       []option.LXFinalMaskLengthRange
	written      atomic.Bool
	writeMu      sync.Mutex
	closeOnce    sync.Once
	closed       chan struct{}
	deadlineMu   sync.Mutex
	deadline     time.Time
	deadlineChanged chan struct{}
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
	delays, _ := o.DelayRanges()
	return &lxFinalMaskConn{
		Conn: c, lengths: lengths, minLength: minLength, maxLo: maxLo, maxHi: maxHi,
		delays: delays, closed: make(chan struct{}), deadlineChanged: make(chan struct{}),
	}
}
func (c *lxFinalMaskConn) Write(p []byte) (int, error) {
	if len(p) == 0 || c.written.Load() {
		return c.Conn.Write(p)
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.written.Load() {
		return c.Conn.Write(p)
	}
	defer c.written.Store(true)
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
	// The Xray merge rule is exactly one delay range with max=0.
	if len(c.delays) != 1 || c.delays[0].Max != 0 {
		if err := c.writeDelayedRecords(out); err != nil {
			return 0, err
		}
		if tail := p[5+n:]; len(tail) != 0 {
			wrote, err := c.Conn.Write(tail)
			if err != nil {
				return 5+n+wrote, err
			}
			if wrote != len(tail) {
				return 5+n+wrote, io.ErrShortWrite
			}
		}
		return len(p), nil
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
func (c *lxFinalMaskConn) WriterReplaceable() bool { return c.written.Load() }
func (c *lxFinalMaskConn) Upstream() any           { return c.Conn }

const lxFinalMaskMaxDelayBudget = 5 * time.Second

func (c *lxFinalMaskConn) delayRange(index int) option.LXFinalMaskLengthRange {
	if index >= len(c.delays) {
		index = len(c.delays) - 1
	}
	return c.delays[index]
}

// The complete record plan is already in memory. Reject excessive worst-case
// delay before sending anything, rather than silently truncating a profile.
func (c *lxFinalMaskConn) writeDelayedRecords(records []byte) error {
	var budget time.Duration
	index := 0
	for off := 0; off < len(records); index++ {
		size := 5 + int(binary.BigEndian.Uint16(records[off+3:off+5]))
		budget += time.Duration(c.delayRange(index).Max) * time.Millisecond
		if budget > lxFinalMaskMaxDelayBudget {
			return errors.New("finalmask_fragment delay budget exceeds 5000 ms")
		}
		off += size
	}
	index = 0
	for off := 0; off < len(records); index++ {
		size := 5 + int(binary.BigEndian.Uint16(records[off+3:off+5]))
		wrote, err := c.Conn.Write(records[off:off+size])
		if err != nil {
			return err
		}
		if wrote != size {
			return io.ErrShortWrite
		}
		r := c.delayRange(index)
		ms := r.Min
		if r.Max > r.Min {
			ms += rand.Intn(r.Max - r.Min + 1)
		}
		if err := c.waitFragmentDelay(time.Duration(ms) * time.Millisecond); err != nil {
			return err
		}
		off += size
	}
	return nil
}

func (c *lxFinalMaskConn) waitFragmentDelay(delay time.Duration) error {
	if delay == 0 {
		return nil
	}
	end := time.Now().Add(delay)
	for {
		select {
		case <-c.closed:
			return net.ErrClosed
		default:
		}
		c.deadlineMu.Lock()
		deadline, changed := c.deadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) {
			return os.ErrDeadlineExceeded
		}
		if !now.Before(end) {
			return nil
		}
		wake := end
		if !deadline.IsZero() && deadline.Before(wake) {
			wake = deadline
		}
		timer := time.NewTimer(time.Until(wake))
		select {
		case <-c.closed:
			timer.Stop()
			return net.ErrClosed
		case <-changed:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (c *lxFinalMaskConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func (c *lxFinalMaskConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetWriteDeadline(t); err != nil {
		return err
	}
	c.deadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	return nil
}

func (c *lxFinalMaskConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetDeadline(t); err != nil {
		return err
	}
	c.deadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
	return nil
}
