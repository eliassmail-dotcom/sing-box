package finalmask

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	noiseMaxPacket=1200
	noiseMaxItems=16
	noiseMaxBurst=8192
	noiseMaxDelay=1000
	noiseMaxReset=86400
)

type udpNoiseSettings struct {
	Reset json.RawMessage `json:"reset"`
	Noise []udpNoiseItemJSON `json:"noise"`
	Script string `json:"script"`
}
type udpNoiseItemJSON struct {
	Rand json.RawMessage `json:"rand"`
	RandRange json.RawMessage `json:"randRange"`
	Type string `json:"type"`
	Packet json.RawMessage `json:"packet"`
	Delay json.RawMessage `json:"delay"`
}
type udpNoiseSegment struct {
	kind string
	data []byte
	lo,hi int
	valueLo,valueHi int
}
type udpNoiseItem struct {
	segments []udpNoiseSegment
	delayLo,delayHi int
}
type udpNoiseConfig struct {
	items []udpNoiseItem
	resetLo,resetHi int
}

var udpNoiseExp=regexp.MustCompile(`<\s*([a-z]+)(?:\s+([^>]*?))?\s*>`)

func noiseRange(raw json.RawMessage,lo,hi,max int)(int,int,error){
	if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")){return 0,0,errors.New("null noise range")}
	return headerRange(raw,lo,hi,max)
}

func compileNoiseExp(raw json.RawMessage)([]udpNoiseSegment,error){
	var exp string
	if err:=json.Unmarshal(raw,&exp);err!=nil{return nil,err}
	if len(exp)>8192{return nil,errors.New("noise expression too long")}
	matches:=udpNoiseExp.FindAllStringSubmatchIndex(exp,-1)
	if len(matches)==0||len(matches)>64{return nil,errors.New("invalid noise expression size")}
	var out []udpNoiseSegment
	last:=0
	for _,m:=range matches{
		if strings.TrimSpace(exp[last:m[0]])!=""{return nil,errors.New("invalid noise expression syntax")}
		last=m[1]
		kind,arg:=exp[m[2]:m[3]],""
		if m[4]>=0{arg=strings.TrimSpace(exp[m[4]:m[5]])}
		s:=udpNoiseSegment{kind:kind,valueHi:255}
		switch kind{
		case "b":
			h:=strings.TrimPrefix(strings.TrimPrefix(strings.Join(strings.Fields(arg),""),"0x"),"0X")
			if h==""{return nil,errors.New("empty noise bytes")}
			b,err:=hex.DecodeString(h)
			if err!=nil{return nil,err}
			s.data=b;s.hi=len(b)
		case "r","rc","rd":
			if arg==""{return nil,errors.New("missing noise segment length")}
			b,_:=json.Marshal(arg)
			lo,hi,err:=noiseRange(b,0,0,noiseMaxPacket)
			if err!=nil{return nil,err}
			s.lo,s.hi=lo,hi
		case "t","c","n":
			if arg!=""{return nil,errors.New("unexpected noise segment argument")}
			s.hi=4
			if kind=="n"{s.hi=8}
		default:return nil,fmt.Errorf("unsupported noise expression %q",kind)
		}
		out=append(out,s)
	}
	if strings.TrimSpace(exp[last:])!=""{return nil,errors.New("trailing noise expression text")}
	return out,nil
}

func compileUDPNoise(raw json.RawMessage)(*udpNoiseConfig,error){
	var s udpNoiseSettings
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if s.Script!=""{return nil,errors.New("noise Lua scripts are not supported")}
	if len(s.Noise)==0||len(s.Noise)>noiseMaxItems{return nil,errors.New("invalid noise item count")}
	lo,hi,err:=noiseRange(s.Reset,0,0,noiseMaxReset)
	if err!=nil{return nil,err}
	c:=&udpNoiseConfig{resetLo:lo,resetHi:hi}
	burst,delays:=0,0
	for _,item:=range s.Noise{
		var segments []udpNoiseSegment
		rlo,rhi,err:=noiseRange(item.Rand,0,0,noiseMaxPacket)
		if err!=nil{return nil,err}
		if rhi>0&&len(item.Packet)>0{return nil,errors.New("noise rand and packet conflict")}
		vlo,vhi,err:=noiseRange(item.RandRange,0,255,255)
		if err!=nil{return nil,err}
		switch{
		case strings.EqualFold(item.Type,"exp"):
			segments,err=compileNoiseExp(item.Packet)
		case rhi>0:
			segments=[]udpNoiseSegment{{kind:"r",lo:rlo,hi:rhi,valueLo:vlo,valueHi:vhi}}
		default:
			var b []byte
			b,err=headerBytes(item.Packet,item.Type)
			segments=[]udpNoiseSegment{{kind:"b",data:b,hi:len(b)}}
		}
		if err!=nil{return nil,err}
		size:=0
		for _,seg:=range segments{size+=seg.hi}
		dlo,dhi,err:=noiseRange(item.Delay,0,0,noiseMaxDelay)
		if err!=nil{return nil,err}
		burst+=size;delays+=dhi
		if size==0||size>noiseMaxPacket||burst>noiseMaxBurst||delays>noiseMaxDelay{return nil,errors.New("noise burst resource budget exceeded")}
		c.items=append(c.items,udpNoiseItem{segments:segments,delayLo:dlo,delayHi:dhi})
	}
	return c,nil
}

type udpNoiseConn struct {
	net.Conn
	config *udpNoiseConfig
	writeMu sync.Mutex
	next time.Time
	counter uint32
	buf [noiseMaxPacket]byte
	closeOnce sync.Once
	closed chan struct{}
	deadlineMu sync.Mutex
	deadline time.Time
	changed chan struct{}
}

func newUDPNoiseConn(raw net.Conn,c *udpNoiseConfig)*udpNoiseConn{
	return &udpNoiseConn{Conn:raw,config:c,closed:make(chan struct{}),changed:make(chan struct{})}
}

func(c *udpNoiseConn)packet(item udpNoiseItem)([]byte,error){
	p:=c.buf[:0]
	for _,seg:=range item.segments{
		switch seg.kind{
		case "b":p=append(p,seg.data...)
		case "t","c":
			n:=uint32(time.Now().Unix())
			if seg.kind=="c"{c.counter++;n=c.counter}
			p=binary.BigEndian.AppendUint32(p,n)
		case "n":
			b:=c.buf[len(p):len(p)+8]
			if _,err:=rand.Read(b);err!=nil{return nil,err}
			p=p[:len(p)+8]
		default:
			size:=sample(seg.lo,seg.hi)
			b:=c.buf[len(p):len(p)+size]
			if seg.kind=="r"&&(seg.valueLo!=0||seg.valueHi!=255){
				for i:=range b{b[i]=byte(sample(seg.valueLo,seg.valueHi))}
			}else{
				if _,err:=rand.Read(b);err!=nil{return nil,err}
				switch seg.kind{
				case "rc":
					const alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
					for i:=range b{b[i]=alphabet[int(b[i])%len(alphabet)]}
				case "rd":for i:=range b{b[i]='0'+b[i]%10}
				}
			}
			p=p[:len(p)+size]
		}
	}
	return p,nil
}

func(c *udpNoiseConn)Write(p []byte)(int,error){
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err:=c.wait(0);err!=nil{return 0,err}
	now:=time.Now()
	if c.next.IsZero()||(c.config.resetHi>0&&now.After(c.next)){
		for _,item:=range c.config.items{
			b,err:=c.packet(item)
			if err!=nil{return 0,err}
			if len(b)>0{
				n,err:=c.Conn.Write(b)
				if err!=nil{return 0,err}
				if n!=len(b){return 0,io.ErrShortWrite}
			}
			if err:=c.wait(time.Duration(sample(item.delayLo,item.delayHi))*time.Millisecond);err!=nil{return 0,err}
		}
	}
	n,err:=c.Conn.Write(p)
	if err==nil&&n!=len(p){err=io.ErrShortWrite}
	if err==nil{
		// Xray reset is a sliding idle timeout, not a periodic timer.
		c.next=time.Now().Add(time.Duration(sample(c.config.resetLo,c.config.resetHi))*time.Second)
	}
	return n,err
}

func(c *udpNoiseConn)Close()error{
	c.closeOnce.Do(func(){close(c.closed)})
	return c.Conn.Close()
}
func(c *udpNoiseConn)SetDeadline(t time.Time)error{
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err:=c.Conn.SetDeadline(t);err!=nil{return err}
	c.updateDeadline(t)
	return nil
}
func(c *udpNoiseConn)SetWriteDeadline(t time.Time)error{
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if err:=c.Conn.SetWriteDeadline(t);err!=nil{return err}
	c.updateDeadline(t)
	return nil
}
func(c *udpNoiseConn)updateDeadline(t time.Time){
	c.deadline=t
	close(c.changed)
	c.changed=make(chan struct{})
}
func(c *udpNoiseConn)wait(delay time.Duration)error{
	end:=time.Now().Add(delay)
	for{
		select{case <-c.closed:return net.ErrClosed;default:}
		c.deadlineMu.Lock()
		deadline,changed:=c.deadline,c.changed
		c.deadlineMu.Unlock()
		now:=time.Now()
		if !deadline.IsZero()&&!now.Before(deadline){return os.ErrDeadlineExceeded}
		if !now.Before(end){return nil}
		wake:=end
		if !deadline.IsZero()&&deadline.Before(wake){wake=deadline}
		timer:=time.NewTimer(time.Until(wake))
		select{
		case <-c.closed:timer.Stop();return net.ErrClosed
		case <-changed:timer.Stop()
		case <-timer.C:
		}
	}
}

