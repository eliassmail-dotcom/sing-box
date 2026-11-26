package finalmask

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mathrand "math/rand"
	"net"
	"os"
	"sync"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type xdnsPending struct{ id uint16; typ dnsmessage.Type; name string; until time.Time; domain *xdnsConfig }
type xdnsConn struct{
	net.Conn
	cfg *xdnsConfig
	start,closeOnce sync.Once
	closed chan struct{}
	queue chan []byte
	wake chan struct{}
	writeMu,mu sync.Mutex
	clientID [8]byte
	initialized bool
	frag byte
	pending [256]xdnsPending
	next int
	readDeadline time.Time
	changed chan struct{}
	terminal error
}
func newXDNSConn(raw net.Conn,cfg *xdnsConfig)*xdnsConn{
	return &xdnsConn{Conn:raw,cfg:cfg,closed:make(chan struct{}),queue:make(chan []byte,8),wake:make(chan struct{},1),changed:make(chan struct{})}
}
func(c *xdnsConn)ensure(){c.start.Do(func(){go c.reader();go c.poller()})}
func(c *xdnsConn)terminate(err error){
	c.closeOnce.Do(func(){
		c.mu.Lock();c.terminal=err;close(c.closed);c.mu.Unlock()
		_ = c.Conn.Close()
	})
}
func(c *xdnsConn)Close()error{c.terminate(net.ErrClosed);return nil}
func(c *xdnsConn)err()error{
	c.mu.Lock();defer c.mu.Unlock()
	if c.terminal!=nil{return c.terminal};return net.ErrClosed
}
func(c *xdnsConn)send(p []byte)error{
	domain:=c.cfg
	if len(c.cfg.domains)>0{domain=c.cfg.domains[mathrand.Intn(len(c.cfg.domains))]}
	return c.sendDomain(p,domain)
}
func(c *xdnsConn)sendDomain(p []byte,domain *xdnsConfig)error{
	select{case <-c.closed:return c.err();default:}
	if !c.initialized{
		if _,err:=rand.Read(c.clientID[:]);err!=nil{return err}
		c.clientID[0]&=0xfc;c.initialized=true
	}
	if len(p)>domain.capacity-12{c.frag++}
	frames,err:=domain.frames(c.clientID,c.frag,p);if err!=nil{return err}
	for _,frame:=range frames{
		var idBytes [2]byte
		if _,err:=rand.Read(idBytes[:]);err!=nil{return err}
		id:=binary.BigEndian.Uint16(idBytes[:])
		wire,name,err:=domain.query(id,frame);if err!=nil{return err}
		c.mu.Lock()
		slot:=c.next%len(c.pending);c.next++
		c.pending[slot]=xdnsPending{id:id,typ:xdnsQueryType(frame[0]&3),name:name,until:time.Now().Add(10*time.Second),domain:domain}
		c.mu.Unlock()
		n,err:=c.Conn.Write(wire)
		if err==nil&&n!=len(wire){err=io.ErrShortWrite}
		if err!=nil{return err}
	}
	return nil
}
func(c *xdnsConn)Write(p []byte)(int,error){
	if len(p)==0||len(p)>xdnsMaxPayload{return 0,errors.New("invalid XDNS datagram size")}
	c.ensure()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err:=c.send(p);err!=nil{return 0,err}
	for i:=0;i<c.cfg.extraPoll;i++{if err:=c.send(nil);err!=nil{return 0,err}}
	select{case c.wake<-struct{}{}:default:}
	return len(p),nil
}
func(c *xdnsConn)reader(){
	var b [4097]byte
	for{
		n,err:=c.Conn.Read(b[:])
		if err!=nil{c.terminate(err);return}
		if n>4096{continue}
		var msg dnsmessage.Message
		if msg.Unpack(b[:n])!=nil||len(msg.Questions)!=1{continue}
		name:=msg.Questions[0].Name.String()
		c.mu.Lock()
		found:=-1
		now:=time.Now()
		for i,p:=range c.pending{if p.id==msg.Header.ID&&p.typ==msg.Questions[0].Type&&p.name!=""&&strings.EqualFold(p.name,name)&&now.Before(p.until){found=i;break}}
		if found<0{c.mu.Unlock();continue}
		expected:=c.pending[found].name
		domain:=c.pending[found].domain
		if domain==nil{c.mu.Unlock();continue}
		packets,e:=domain.decodeResponse(&msg,expected,c.pending[found].typ)
		if e==nil{c.pending[found]=xdnsPending{}}
		c.mu.Unlock()
		if e!=nil{continue}
		for _,p:=range packets{
			select{case <-c.closed:return;case c.queue<-p:default:}
		}
		if len(packets)>0{select{case c.wake<-struct{}{}:default:}}
	}
}
func(c *xdnsConn)poller(){
	select{case <-c.closed:return;case <-c.wake:}
	delay:=500*time.Millisecond
	timer:=time.NewTimer(delay);defer timer.Stop()
	for{
		select{
		case <-c.closed:return
		case <-c.wake:
			delay=500*time.Millisecond;timer.Reset(delay);continue
		case <-timer.C:
		}
		c.writeMu.Lock()
		err:=c.send(nil)
		for i:=0;i<c.cfg.extraPoll&&err==nil;i++{err=c.send(nil)}
		c.writeMu.Unlock()
		if err!=nil{c.terminate(err);return}
		delay=min(delay*2,10*time.Second);timer.Reset(delay)
	}
}
func(c *xdnsConn)SetReadDeadline(t time.Time)error{
	c.mu.Lock();defer c.mu.Unlock()
	c.readDeadline=t;close(c.changed);c.changed=make(chan struct{})
	return nil
}
func(c *xdnsConn)SetDeadline(t time.Time)error{
	if err:=c.Conn.SetWriteDeadline(t);err!=nil{return err}
	return c.SetReadDeadline(t)
}
func(c *xdnsConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.ensure()
	for{
		c.mu.Lock();deadline,changed:=c.readDeadline,c.changed;c.mu.Unlock()
		var t *time.Timer;var timeout <-chan time.Time
		if !deadline.IsZero(){
			if !time.Now().Before(deadline){return 0,os.ErrDeadlineExceeded}
			t=time.NewTimer(time.Until(deadline));timeout=t.C
		}
		select{
		case <-c.closed:if t!=nil{t.Stop()};return 0,c.err()
		case b:=<-c.queue:if t!=nil{t.Stop()};return copy(p,b),nil
		case <-changed:if t!=nil{t.Stop()}
		case <-timeout:
		}
	}
}
