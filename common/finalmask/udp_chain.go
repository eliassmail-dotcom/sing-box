package finalmask

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
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

type UDPChain struct { masks []udpMask }
type udpMask struct { password []byte; geckoMin,geckoMax int; noise *udpNoiseConfig }
type salamanderSettings struct { Password string `json:"password"`; PacketSize json.RawMessage `json:"packetSize,omitempty"` }

// NewUDPChain validates the supported client subset. Reject unsupported
// variants rather than silently connecting without a required server mask.
func NewUDPChain(opts []option.LXFinalMaskUDPMaskOptions)(*UDPChain,error){
	if len(opts)==0{return nil,nil}
	if len(opts)>2{return nil,errors.New("finalmask_udp: at most two masks")}
	c:=&UDPChain{}
	seen:=make(map[string]bool)
	for i,o:=range opts{
		if seen[o.Type]{return nil,fmt.Errorf("finalmask_udp[%d]: duplicate mask",i)}
		seen[o.Type]=true
		var m udpMask
		switch o.Type{
		case "salamander":
			var settings salamanderSettings
			if err:=decodeMaskSettings(o.Settings,&settings);err!=nil{return nil,err}
			if len(settings.Password)<4||len(settings.Password)>1024{return nil,errors.New("finalmask_udp: salamander password length must be 4-1024 bytes")}
			lo,hi,err:=headerRange(settings.PacketSize,0,0,2048)
			if err!=nil || (hi>0 && lo==0) {return nil,errors.New("finalmask_udp: invalid gecko packetSize")}
			m.password=[]byte(settings.Password)
			m.geckoMin,m.geckoMax=lo,hi
		case "noise":
			cfg,err:=compileUDPNoise(o.Settings)
			if err!=nil{return nil,fmt.Errorf("finalmask_udp[%d]: %w",i,err)}
			m.noise=cfg
		default:return nil,fmt.Errorf("finalmask_udp[%d]: unsupported mask %q",i,o.Type)
		}
		c.masks=append(c.masks,m)
	}
	return c,nil
}

// First configured entry is outermost, as in the Xray wrapper stack.
func(c *UDPChain) WrapConnected(raw net.Conn)net.Conn{
	if c==nil{return raw}
	conn:=raw
	for i:=len(c.masks)-1;i>=0;i--{
		m:=c.masks[i]
		if m.noise!=nil{conn=newUDPNoiseConn(conn,m.noise);continue}
		conn=&salamanderUDPConn{Conn:conn,password:m.password}
		if m.geckoMax>0{conn=&geckoUDPConn{Conn:conn,minPkt:m.geckoMin,maxPkt:m.geckoMax}}
	}
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
