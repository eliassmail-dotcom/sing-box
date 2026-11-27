package finalmask

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"sync"
	"time"
)

const (
	geckoHeader=5
	geckoMaxPayload=udpWireLimit-salamanderSalt
	geckoSlots=8
	geckoTTL=8*time.Second
)

// The connected transport has one remote endpoint. Bound reassembly to
// eight messages and 4088 bytes each; no per-connection GC goroutine.
type geckoUDPConn struct {
	net.Conn
	minPkt,maxPkt int
	readMu,writeMu sync.Mutex
	id uint8
	slots [geckoSlots]geckoAssembly
	readBuf [geckoMaxPayload]byte
	writeBuf [geckoMaxPayload]byte
}
type geckoAssembly struct {
	id,count,seen uint8
	used bool
	expires time.Time
	total int
	chunks [8][]byte
}

func(c *geckoUDPConn)Write(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	if len(p)>geckoMaxPayload{return 0,errors.New("finalmask_udp: gecko datagram too large")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if p[0]&0x80==0{return c.Conn.Write(p)}
	count:=2+mathrand.Intn(7)
	size:=len(p)/count
	c.id++
	for i:=0;i<count;i++{
		start,end:=i*size,(i+1)*size
		if i==count-1{end=len(p)}
		chunk:=p[start:end]
		base:=salamanderSalt+geckoHeader+len(chunk)
		padding:=0
		if lo:=max(c.minPkt,base);lo<=c.maxPkt {
			padding=lo-base+mathrand.Intn(c.maxPkt-lo+1)
		}
		frame:=c.writeBuf[:geckoHeader+padding+len(chunk)]
		frame[0]=0x80
		frame[1]=c.id
		frame[2]=byte(i<<4|count)
		binary.BigEndian.PutUint16(frame[3:5],uint16(padding))
		if _,err:=rand.Read(frame[5:5+padding]);err!=nil{return 0,err}
		copy(frame[5+padding:],chunk)
		n,err:=c.Conn.Write(frame)
		if err!=nil{return 0,err}
		if n!=len(frame){return 0,io.ErrShortWrite}
	}
	return len(p),nil
}

func(c *geckoUDPConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		n,err:=c.Conn.Read(c.readBuf[:])
		if err!=nil{return 0,err}
		if n==0{continue}
		frame:=c.readBuf[:n]
		if frame[0]&0x80==0{return copy(p,frame),nil}
		if n<geckoHeader{continue}
		idx,count:=frame[2]>>4,frame[2]&15
		pad:=int(binary.BigEndian.Uint16(frame[3:5]))
		if count<2||count>8||idx>=count||pad>n-geckoHeader{continue}
		if n,ok:=c.accept(p,frame[1],idx,count,frame[5+pad:],time.Now());ok{return n,nil}
	}
}

func(c *geckoUDPConn)accept(dst []byte,id,idx,count uint8,payload []byte,now time.Time)(int,bool){
	var slot *geckoAssembly
	var free *geckoAssembly
	for i:=range c.slots {
		s:=&c.slots[i]
		if s.used&&!now.Before(s.expires){*s=geckoAssembly{}}
		if s.used&&s.id==id{slot=s}
		if !s.used&&free==nil{free=s}
	}
	if slot==nil {
		if free==nil{return 0,false}
		slot=free
		*slot=geckoAssembly{id:id,count:count,used:true,expires:now.Add(geckoTTL)}
	}
	bit:=uint8(1)<<idx
	if slot.count!=count||slot.seen&bit!=0{return 0,false}
	if len(payload)>geckoMaxPayload-slot.total {
		*slot=geckoAssembly{}
		return 0,false
	}
	slot.chunks[idx]=append([]byte(nil),payload...)
	slot.total+=len(payload)
	slot.seen|=bit
	if uint16(slot.seen)!=(uint16(1)<<count)-1{return 0,false}
	n:=0
	for _,chunk:=range slot.chunks[:count]{n+=copy(dst[n:],chunk)}
	*slot=geckoAssembly{}
	return n,true
}
