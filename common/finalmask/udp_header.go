package finalmask

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing-box/option"
)

const (
	udpHeaderMax=512
	udpHeaderMaxItems=64
	udpHeaderStateTTL=5*time.Second
)

type udpHeaderItemJSON struct {
	Rand int `json:"rand"`
	RandRange json.RawMessage `json:"randRange"`
	Type string `json:"type"`
	Packet json.RawMessage `json:"packet"`
	Capture string `json:"capture"`
	Reuse string `json:"reuse"`
	Transform json.RawMessage `json:"transform"`
}
type udpHeaderJSON struct {
	Mode string `json:"mode"`
	Client []udpHeaderItemJSON `json:"client"`
	Server []udpHeaderItemJSON `json:"server"`
}
type udpHeaderConfig struct {
	client,server []headerItem
	sendSize,receiveSize int
}

func udpHeaderUsesMetadata(e *headerExpr)bool{
	if e==nil{return false}
	if e.kind=="metadata"{return true}
	for _,a:=range e.args{if udpHeaderUsesMetadata(a){return true}}
	return false
}

func compileUDPHeader(raw json.RawMessage)(*udpHeaderConfig,error){
	var s udpHeaderJSON
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if s.Mode!=""&&s.Mode!="prefix"{return nil,errors.New("only UDP header-custom prefix mode is supported")}
	if len(s.Client)+len(s.Server)==0||len(s.Client)+len(s.Server)>udpHeaderMaxItems{return nil,errors.New("invalid UDP header item count")}
	convert:=func(in []udpHeaderItemJSON)[]option.LXFinalMaskTCPHeaderItem{
		out:=make([]option.LXFinalMaskTCPHeaderItem,0,len(in))
		for _,i:=range in{
			out=append(out,option.LXFinalMaskTCPHeaderItem{Rand:i.Rand,RandRange:i.RandRange,Type:i.Type,Packet:i.Packet,Capture:i.Capture,Reuse:i.Reuse,Transform:i.Transform})
		}
		return out
	}
	// A single outbound/inbound round has the same dependency order as
	// Xray's prefix sizing. Reuse the TCP expression compiler, not its IO.
	h,err:=NewTCPHeader(&option.LXFinalMaskTCPHeaderOptions{
		Clients:[][]option.LXFinalMaskTCPHeaderItem{convert(s.Client)},
		Servers:[][]option.LXFinalMaskTCPHeaderItem{convert(s.Server)},
	})
	if err!=nil{return nil,err}
	c:=&udpHeaderConfig{client:h.clients[0],server:h.servers[0]}
	sizes:=make(map[string]int)
	measure:=func(items []headerItem,receiving bool)(int,error){
		total:=0
		for _,item:=range items{
			size:=len(item.packet)+item.random
			if item.reuse!=""{size=sizes[item.reuse]}
			if item.transform!=nil{
				if receiving&&udpHeaderUsesMetadata(item.transform){return 0,errors.New("UDP receive expressions cannot use socket metadata")}
				size=item.transform.width
			}
			if item.capture!=""{sizes[item.capture]=size}
			total+=size
			if total>udpHeaderMax{return 0,errors.New("UDP header exceeds 512 bytes")}
		}
		return total,nil
	}
	c.sendSize,err=measure(c.client,false)
	if err!=nil{return nil,err}
	c.receiveSize,err=measure(c.server,true)
	if err!=nil{return nil,err}
	if c.sendSize+c.receiveSize==0{return nil,errors.New("empty UDP header")}
	return c,nil
}

type udpHeaderConn struct {
	net.Conn
	config *udpHeaderConfig
	readMu,writeMu,stateMu sync.Mutex
	vars map[string][]byte
	expires time.Time
	rbuf [udpWireLimit+1]byte
	wbuf [udpWireLimit]byte
}

func udpHeaderValue(item headerItem,vars map[string][]byte,metadata map[string]uint64)([]byte,error){
	if item.reuse!=""{
		b,ok:=vars[item.reuse]
		if !ok{return nil,fmt.Errorf("missing UDP header variable %q",item.reuse)}
		return b,nil
	}
	if item.transform!=nil{
		v,err:=item.transform.eval(vars,metadata)
		return v.b,err
	}
	return item.packet,nil
}

// Snapshot values are immutable; each new capture owns a copy. Invalid
// datagrams never commit a partial update. There is only one peer per conn.
func(c *udpHeaderConn)snapshot()map[string][]byte{
	v:=make(map[string][]byte)
	if time.Now().Before(c.expires){
		for key,value:=range c.vars{v[key]=value}
	}
	return v
}
func(c *udpHeaderConn)commit(v map[string][]byte){
	c.vars=v
	c.expires=time.Now().Add(udpHeaderStateTTL)
}

func(c *udpHeaderConn)Write(p []byte)(int,error){
	if len(p)>udpWireLimit-c.config.sendSize{return 0,errors.New("UDP header datagram too large")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	// Serialize state commit with receive matching so an immediate reply
	// cannot observe pre-write captures. No lock across a blocking Read.
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	vars:=c.snapshot()
	metadata:=headerMetadata(c.Conn)
	wire:=c.wbuf[:0]
	for _,item:=range c.config.client{
		var b []byte
		var err error
		if item.random>0{b,err=headerRandom(item)}else{b,err=udpHeaderValue(item,vars,metadata)}
		if err!=nil{return 0,err}
		if item.capture!=""{vars[item.capture]=bytes.Clone(b)}
		wire=append(wire,b...)
	}
	if len(wire)!=c.config.sendSize{return 0,errors.New("UDP header send width changed")}
	wire=append(wire,p...)
	n,err:=c.Conn.Write(wire)
	if err!=nil{return 0,err}
	if n!=len(wire){return 0,io.ErrShortWrite}
	c.commit(vars)
	return len(p),nil
}

func(c *udpHeaderConn)match(wire []byte)bool{
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	vars:=c.snapshot()
	off:=0
	for _,item:=range c.config.server{
		expected,err:=udpHeaderValue(item,vars,nil)
		if err!=nil{return false}
		size:=len(expected)+item.random
		if size>len(wire)-off{return false}
		b:=wire[off:off+size]
		if item.random==0&&!bytes.Equal(b,expected){return false}
		if item.capture!=""{vars[item.capture]=bytes.Clone(b)}
		off+=size
	}
	if off!=c.config.receiveSize{return false}
	c.commit(vars)
	return true
}

func(c *udpHeaderConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for{
		n,err:=c.Conn.Read(c.rbuf[:])
		if err!=nil{return 0,err}
		if n<c.config.receiveSize||n>udpWireLimit{continue}
		if !c.match(c.rbuf[:c.config.receiveSize]){continue}
		return copy(p,c.rbuf[c.config.receiveSize:n]),nil
	}
}
