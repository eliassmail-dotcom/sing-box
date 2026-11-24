package tls

import (
	"bytes"
	"encoding/binary"
	"github.com/sagernet/sing-box/option"
	"net"
	"testing"
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
	for _, v := range []option.LXFinalMaskFragmentOptions{{Packets: "all", Length: "10-20", Delay: "0"}, {Packets: "tlshello", Length: "0-20", Delay: "0"}, {Packets: "tlshello", Length: "20-10", Delay: "0"}, {Packets: "tlshello", Length: "10-20", Delay: "1"}} {
		if v.Validate() == nil {
			t.Fatal("invalid options accepted")
		}
	}
}
