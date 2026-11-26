package tls

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"errors"
	"io"
	"os"
	"time"

	"github.com/sagernet/sing-box/option"
)

type lxFinalMaskCapture struct {
	net.Conn
	writes [][]byte
}

func (c *lxFinalMaskCapture) Write(b []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}
func TestLXFinalMaskRecordReassembly(t *testing.T) {
	payload := make([]byte, 1903)
	payload[0] = 1
	for i := 1; i < len(payload); i++ {
		payload[i] = byte(i)
	}
	first := []byte{22, 3, 1, 0, 0}
	binary.BigEndian.PutUint16(first[3:5], uint16(len(payload)))
	first = append(first, payload...)
	tail := []byte{20, 3, 3, 0, 1, 1}
	first = append(first, tail...)
	cap := &lxFinalMaskCapture{}
	c := newLXFinalMaskConn(cap, &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "10-20", Delay: "0"})
	if n, e := c.Write(first); e != nil || n != len(first) {
		t.Fatalf("write %d %v", n, e)
	}
	if len(cap.writes) != 1 {
		t.Fatal("expected single underlying write")
	}
	wire := cap.writes[0]
	var got []byte
	count := 0
	for len(wire) > len(tail) {
		if len(wire) < 5 || !bytes.Equal(wire[:3], first[:3]) {
			t.Fatal("invalid record")
		}
		n := int(binary.BigEndian.Uint16(wire[3:5]))
		if n < 1 || n > 20 || len(wire) < n+5 {
			t.Fatal("invalid length")
		}
		if len(wire) > n+5+len(tail) && n < 10 {
			t.Fatal("short non-final record")
		}
		got = append(got, wire[5:5+n]...)
		wire = wire[5+n:]
		count++
	}
	if count < 90 || !bytes.Equal(got, payload) || !bytes.Equal(wire, tail) {
		t.Fatal("changed payload or trailing record")
	}
	c.Write([]byte("unchanged"))
	if string(cap.writes[1]) != "unchanged" {
		t.Fatal("second write changed")
	}
}
func TestLXFinalMaskValidation(t *testing.T) {
	for _, v := range []option.LXFinalMaskFragmentOptions{{Packets: "all", Length: "10-20", Delay: "0"}, {Packets: "tlshello", Length: "0-20", Delay: "0"}, {Packets: "tlshello", Length: "20-10", Delay: "0"}, {Packets: "tlshello", Length: "10-20", Delay: "-1"}} {
		if v.Validate() == nil {
			t.Fatal("invalid options accepted")
		}
	}
}

func TestLXFinalMaskMaxSplit(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 100)
	payload[0] = 1
	input := append([]byte{22, 3, 1, 0, byte(len(payload))}, payload...)
	tail := []byte{20, 3, 3, 0, 1, 1}
	input = append(input, tail...)
	for _, tc := range []struct {
		cap string
		min, max int
	}{{"", 10, 10}, {"0", 10, 10}, {"1", 1, 1}, {"3", 3, 3}, {"2-4", 2, 4}, {"20", 10, 10}} {
		t.Run(tc.cap, func(t *testing.T) {
			for i := 0; i < 20; i++ {
				opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "10", Delay: "0", MaxSplit: tc.cap}
				if err := opts.Validate(); err != nil { t.Fatal(err) }
				capture := &lxFinalMaskCapture{}
				conn := newLXFinalMaskConn(capture, opts)
				if n, err := conn.Write(input); err != nil || n != len(input) { t.Fatalf("write %d %v", n, err) }
				if len(capture.writes) != 1 { t.Fatal("expected one write") }
				wire := capture.writes[0]
				var restored []byte
				count := 0
				for len(wire) > len(tail) {
					if len(wire) < 5 || !bytes.Equal(wire[:3], input[:3]) { t.Fatal("invalid record") }
					size := int(binary.BigEndian.Uint16(wire[3:5]))
					if size < 1 || size > len(wire)-5-len(tail) { t.Fatal("invalid length") }
					restored = append(restored, wire[5:5+size]...)
					wire = wire[5+size:]
					count++
				}
				if count < tc.min || count > tc.max || !bytes.Equal(restored, payload) || !bytes.Equal(wire, tail) {
					t.Fatalf("split count %d; expected %d-%d; payload or tail mismatch", count, tc.min, tc.max)
				}
			}
		})
	}
}

func TestLXFinalMaskMaxSplitValidation(t *testing.T) {
	for _, value := range []string{"-1", "4-2", "1-2-3", "no", "16385"} {
		opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "10", Delay: "0", MaxSplit: value}
		if opts.Validate() == nil { t.Fatalf("accepted invalid max_split %q", value) }
	}
}

func TestLXFinalMaskLengthSequence(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 34)
	payload[0] = 1
	input := append([]byte{22, 3, 1, 0, byte(len(payload))}, payload...)
	tail := []byte{20, 3, 3, 0, 1, 1}
	input = append(input, tail...)
	for _, tc := range []struct {
		name string
		maxSplit string
		want []int
	}{
		{"repeat last", "", []int{4, 8, 8, 8, 6}},
		{"cap", "3", []int{4, 8, 22}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "99", Lengths: []string{"4", "8"}, Delay: "0", MaxSplit: tc.maxSplit}
			if err := opts.Validate(); err != nil { t.Fatal(err) }
			capture := &lxFinalMaskCapture{}
			conn := newLXFinalMaskConn(capture, opts)
			if n, err := conn.Write(input); err != nil || n != len(input) { t.Fatalf("write %d %v", n, err) }
			if len(capture.writes) != 1 { t.Fatal("expected one write") }
			wire := capture.writes[0]
			var restored []byte
			for _, size := range tc.want {
				if len(wire) < 5+size || !bytes.Equal(wire[:3], input[:3]) || int(binary.BigEndian.Uint16(wire[3:5])) != size {
					t.Fatalf("expected record size %d", size)
				}
				restored = append(restored, wire[5:5+size]...)
				wire = wire[5+size:]
			}
			if !bytes.Equal(restored, payload) || !bytes.Equal(wire, tail) { t.Fatal("payload or tail mismatch") }
		})
	}
}
func TestLXFinalMaskLengthSequenceValidation(t *testing.T) {
	for _, ranges := range [][]string{{"0", "4"}, {"4", "0"}, {"4", "9-3"}, {"4", "16385"}, {"4", ""}, make([]string, 257)} {
		opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Lengths: ranges, Delay: "0"}
		if opts.Validate() == nil { t.Fatalf("accepted invalid lengths %v", ranges) }
	}
	opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Lengths: []string{"2-3", "5-6"}, Delay: "0"}
	if err := opts.Validate(); err != nil { t.Fatal(err) }
}

func TestLXFinalMaskDelaySequence(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 12)
	payload[0] = 1
	input := append([]byte{22, 3, 1, 0, byte(len(payload))}, payload...)
	tail := []byte{20, 3, 3, 0, 1, 1}
	input = append(input, tail...)
	opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "4", Delay: "0", Delays: []string{"1", "0"}}
	if err := opts.Validate(); err != nil { t.Fatal(err) }
	capture := &lxFinalMaskCapture{}
	conn := newLXFinalMaskConn(capture, opts)
	if n, err := conn.Write(input); err != nil || n != len(input) { t.Fatalf("write %d %v", n, err) }
	if len(capture.writes) != 4 { t.Fatalf("got %d writes, want 3 records and tail", len(capture.writes)) }
	var restored []byte
	for _, record := range capture.writes[:3] {
		if len(record) != 9 || int(binary.BigEndian.Uint16(record[3:5])) != 4 { t.Fatal("bad record") }
		restored = append(restored, record[5:]...)
	}
	if !bytes.Equal(restored, payload) || !bytes.Equal(capture.writes[3], tail) { t.Fatal("changed data") }
}

func TestLXFinalMaskDelayBudget(t *testing.T) {
	opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "4", Delay: "3000"}
	if err := opts.Validate(); err != nil { t.Fatal(err) }
	capture := &lxFinalMaskCapture{}
	conn := newLXFinalMaskConn(capture, opts)
	input := []byte{22, 3, 1, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}
	if _, err := conn.Write(input); err == nil || len(capture.writes) != 0 { t.Fatal("delay budget must reject before writing") }
}

func TestLXFinalMaskDelayInterrupted(t *testing.T) {
	for _, tc := range []struct { name string; interrupt func(net.Conn) error; want error }{
		{"close", func(c net.Conn) error { return c.Close() }, net.ErrClosed},
		{"deadline", func(c net.Conn) error { return c.SetWriteDeadline(time.Now().Add(-time.Millisecond)) }, os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, peer := net.Pipe()
			defer raw.Close()
			defer peer.Close()
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil { t.Fatal(err) }
			opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "4", Delay: "2000"}
			conn := newLXFinalMaskConn(raw, opts)
			result := make(chan error, 1)
			go func() { _, err := conn.Write([]byte{22, 3, 1, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}); result <- err }()
			record := make([]byte, 9)
			if _, err := io.ReadFull(peer, record); err != nil { t.Fatal(err) }
			if err := tc.interrupt(conn); err != nil { t.Fatal(err) }
			select {
			case err := <-result:
				if !errors.Is(err, tc.want) { t.Fatalf("got %v, want %v", err, tc.want) }
			case <-time.After(time.Second):
				t.Fatal("delay did not stop promptly")
			}
		})
	}
}

func TestLXFinalMaskDelayValidation(t *testing.T) {
	for _, value := range []string{"-1", "4-2", "5001", "bad"} {
		opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "4", Delay: value}
		if opts.Validate() == nil { t.Fatalf("accepted invalid delay %q", value) }
	}
	for _, delays := range [][]string{{"0", "bad"}, {"1", "2-1"}, make([]string, 257)} {
		opts := &option.LXFinalMaskFragmentOptions{Packets: "tlshello", Length: "4", Delays: delays}
		if opts.Validate() == nil { t.Fatal("accepted invalid delays") }
	}
}
