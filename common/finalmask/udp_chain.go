package finalmask

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/sagernet/sing-box/option"
	"golang.org/x/crypto/blake2b"
)

const (
	udpWireLimit = 4096
	salamanderSalt = 8
)

type UDPChain struct { password []byte; geckoMin,geckoMax int }
type salamanderSettings struct { Password string `json:"password"`; PacketSize json.RawMessage `json:"packetSize,omitempty"` }

// NewUDPChain validates the supported client subset. Reject unsupported
// variants rather than silently connecting without a required server mask.
func NewUDPChain(opts []option.LXFinalMaskUDPMaskOptions)(*UDPChain,error){
	if len(opts)==0{return nil,nil}
	if len(opts)!=1||opts[0].Type!="salamander"{return nil,errors.New("finalmask_udp: only a single salamander mask is supported")}
	var settings salamanderSettings
	if err:=decodeMaskSettings(opts[0].Settings,&settings);err!=nil{return nil,err}
	if len(settings.Password)<4||len(settings.Password)>1024{return nil,errors.New("finalmask_udp: salamander password length must be 4-1024 bytes")}
	lo,hi,err:=headerRange(settings.PacketSize,0,0,2048)
	if err!=nil || (hi>0 && lo==0) {return nil,errors.New("finalmask_udp: invalid gecko packetSize")}
	return &UDPChain{password:[]byte(settings.Password),geckoMin:lo,geckoMax:hi},nil
}

// A connected datagram stream: every Write corresponds to one UDP packet.
// Never exposes the underlying socket as a replaceable reader/writer.
func(c *UDPChain) WrapConnected(raw net.Conn)net.Conn{
	if c==nil{return raw}
	var conn net.Conn=&salamanderUDPConn{Conn:raw,password:c.password}
	if c.geckoMax>0 {conn=&geckoUDPConn{Conn:conn,minPkt:c.geckoMin,maxPkt:c.geckoMax}}
	return conn
}

type salamanderUDPConn struct {
	net.Conn
	password []byte
	readMu,writeMu sync.Mutex
	rbuf [udpWireLimit+1]byte
	wbuf [udpWireLimit]byte
}

func salamanderXOR(password,salt,src,dst []byte){
	var input [1024+salamanderSalt]byte
	n:=copy(input[:],password)
	copy(input[n:],salt)
	key:=blake2b.Sum256(input[:n+salamanderSalt])
	for i,b:=range src{dst[i]=b^key[i%len(key)]}
}

func(c *salamanderUDPConn)Write(p []byte)(int,error){
	if len(p)>udpWireLimit-salamanderSalt{return 0,errors.New("finalmask_udp: datagram too large")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire:=c.wbuf[:len(p)+salamanderSalt]
	if _,err:=rand.Read(wire[:salamanderSalt]);err!=nil{return 0,err}
	salamanderXOR(c.password,wire[:salamanderSalt],p,wire[salamanderSalt:])
	n,err:=c.Conn.Write(wire)
	if err!=nil{return 0,err}
	if n!=len(wire){return 0,io.ErrShortWrite}
	return len(p),nil
}

func(c *salamanderUDPConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for{
		n,err:=c.Conn.Read(c.rbuf[:])
		if err!=nil{return 0,err}
		if n<=salamanderSalt||n>udpWireLimit{continue}
		body:=c.rbuf[salamanderSalt:n]
		salamanderXOR(c.password,c.rbuf[:salamanderSalt],body,body)
		return copy(p,body),nil
	}
}
