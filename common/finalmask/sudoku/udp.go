// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// Adapted from XTLS/Xray-core, 676eaf66f8f05d4d558ee7a74b4736623d3feeb9,
// transport/internet/finalmask/sudoku/conn_udp.go. See UPSTREAM.md.

package sudoku

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/common/lxnet"
)

const (
	udpPayloadLimit = 2048
	// Four hints, at most five padding bytes per input byte, one final pad.
	udpEncodedLimit = 9*udpPayloadLimit+1
)

// WrapUDP uses classic hints in both directions. Unlike the TCP stream,
// the table rotation and padding choice restart for each datagram.
func(m *Mask)WrapUDP(raw net.Conn)net.Conn{
	return &udpConn{Conn:raw,mask:m}
}

type udpConn struct {
	net.Conn
	mask *Mask
	readMu,writeMu sync.Mutex
	readBuf [udpEncodedLimit+1]byte
}

func(c *udpConn)Write(p []byte)(int,error){
	if len(p)>udpPayloadLimit{return 0,errors.New("sudoku UDP payload exceeds 2048 bytes")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	encoded,err:=newCodec(c.mask.tables,c.mask.pMin,c.mask.pMax).encode(p)
	if err!=nil{return 0,err}
	if len(encoded)>udpEncodedLimit{return 0,errors.New("sudoku UDP encoded datagram too large")}
	n,err:=c.Conn.Write(encoded)
	if err!=nil{return 0,err}
	if n!=len(encoded){return 0,io.ErrShortWrite}
	return len(p),nil
}

func(c *udpConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for{
		n,err:=c.Conn.Read(c.readBuf[:])
		// Windows reports WSAEMSGSIZE rather than a successful truncated
		// read. Discard the entire oversized datagram on either platform.
		if lxnet.IsTruncatedDatagramRead(err){continue}
		if err!=nil{return 0,err}
		if n>udpEncodedLimit{continue}
		idx:=0
		var hintStorage [4]byte
		var decodedStorage [udpEncodedLimit/4+1]byte
		hints,decoded,err:=decodeBytes(c.mask.tables,&idx,c.readBuf[:n],hintStorage[:0],decodedStorage[:0])
		if err!=nil||len(hints)!=0||len(decoded)>udpPayloadLimit||len(decoded)>len(p){continue}
		return copy(p,decoded),nil
	}
}
