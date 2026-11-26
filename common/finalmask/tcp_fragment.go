// Package finalmask implements opt-in transport connection masks. The first
// raw TCP fragment mode follows Xray v26.11.9 write-index and range semantics,
// adapted to net.Conn cancellation and bounded work on mobile clients.
package finalmask

import (
	"errors"
	"io"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

const (
	maxSegments = 16384
	maxDelayBudget = 5 * time.Second
)

// TCPFragment is immutable after construction and reusable across connections.
type TCPFragment struct {
	from, to uint64
	lengths, delays []option.LXFinalMaskLengthRange
	maxLo, maxHi int
}

func NewTCPFragment(o *option.LXFinalMaskFragmentOptions) (*TCPFragment, error) {
	if o == nil {
		return nil, nil
	}
	from, to, err := o.TCPPacketRange()
	if err != nil { return nil, err }
	lengths, err := o.TCPFragmentLengthRanges()
	if err != nil { return nil, err }
	delays, err := o.DelayRanges()
	if err != nil { return nil, err }
	lo, hi, err := o.MaxSplitBounds()
	if err != nil { return nil, err }
	return &TCPFragment{from: from, to: to, lengths: lengths, delays: delays, maxLo: lo, maxHi: hi}, nil
}

func (f *TCPFragment) Wrap(c net.Conn) net.Conn {
	return &tcpFragmentConn{Conn: c, config: f, closed: make(chan struct{}), deadlineChanged: make(chan struct{})}
}

type tcpFragmentConn struct {
	net.Conn
	config *TCPFragment
	writeMu sync.Mutex
	count uint64
	closeOnce sync.Once
	closed chan struct{}
	deadlineMu sync.Mutex
	deadline time.Time
	deadlineChanged chan struct{}
}

func at(ranges []option.LXFinalMaskLengthRange, index int) option.LXFinalMaskLengthRange {
	if index >= len(ranges) { index = len(ranges)-1 }
	return ranges[index]
}

func sample(lo, hi int) int {
	if lo == hi { return lo }
	return lo + rand.Intn(hi-lo+1)
}

// Preflight the conservative worst case without allocating a per-segment
// buffer. Reject expensive configurations before any part of the write leaves.
func (f *TCPFragment) checkBudget(length, limit int) error {
	var budget time.Duration
	for index, left := 0, length; left > 0; index++ {
		if index >= maxSegments {
			return errors.New("finalmask_tcp_fragment segment budget exceeded")
		}
		budget += time.Duration(at(f.delays, index).Max) * time.Millisecond
		if budget > maxDelayBudget {
			return errors.New("finalmask_tcp_fragment delay budget exceeded")
		}
		if limit > 0 && index+1 >= limit { return nil }
		left -= at(f.lengths, index).Min
	}
	return nil
}

func (c *tcpFragmentConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 { return c.Conn.Write(p) }
	c.count++
	f := c.config
	if f.from != 0 && (c.count < f.from || c.count > f.to) {
		return c.Conn.Write(p)
	}
	limit := sample(f.maxLo, f.maxHi)
	if err := f.checkBudget(len(p), limit); err != nil { return 0, err }
	total := 0
	for index := 0; total < len(p); index++ {
		r := at(f.lengths, index)
		size := sample(r.Min, r.Max)
		if size > len(p)-total || (limit > 0 && index+1 >= limit) {
			size = len(p)-total
		}
		n, err := c.Conn.Write(p[total:total+size])
		total += n
		if err != nil { return total, err }
		if n != size { return total, io.ErrShortWrite }
		d := at(f.delays, index)
		if err := c.wait(time.Duration(sample(d.Min,d.Max))*time.Millisecond); err != nil {
			return total, err
		}
	}
	return total, nil
}

// Do not expose the underlying writer for splice or buffer-copy shortcuts;
// those can bypass an active write-index mask. TCP writes may still coalesce
// on the wire (as with any net.Conn implementation).
func (c *tcpFragmentConn) Close() error {
	c.closeOnce.Do(func(){ close(c.closed) })
	return c.Conn.Close()
}

func (c *tcpFragmentConn) SetDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetDeadline(t); err != nil { return err }
	c.setDeadline(t)
	return nil
}

func (c *tcpFragmentConn) SetWriteDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err := c.Conn.SetWriteDeadline(t); err != nil { return err }
	c.setDeadline(t)
	return nil
}

func (c *tcpFragmentConn) setDeadline(t time.Time) {
	c.deadline = t
	close(c.deadlineChanged)
	c.deadlineChanged = make(chan struct{})
}

func (c *tcpFragmentConn) wait(delay time.Duration) error {
	if delay == 0 { return nil }
	end := time.Now().Add(delay)
	for {
		select {
		case <-c.closed: return net.ErrClosed
		default:
		}
		c.deadlineMu.Lock()
		deadline, changed := c.deadline, c.deadlineChanged
		c.deadlineMu.Unlock()
		now := time.Now()
		if !deadline.IsZero() && !now.Before(deadline) { return os.ErrDeadlineExceeded }
		if !now.Before(end) { return nil }
		wake := end
		if !deadline.IsZero() && deadline.Before(wake) { wake = deadline }
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
