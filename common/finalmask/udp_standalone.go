package finalmask

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

const udpStandaloneQueue = 8

type udpStandalonePending struct {
	vars map[string][]byte
	done chan struct{}
}

// A single reader demultiplexes handshake replies and payload datagrams.
// The bounded queue deliberately drops payload on overflow (UDP semantics)
// rather than blocking the handshake or retaining an unbounded backlog.
type udpStandaloneConn struct {
	net.Conn
	config *udpHeaderConfig
	start sync.Once
	closeOnce sync.Once
	closed chan struct{}
	queue chan []byte
	writeMu sync.Mutex
	mu sync.Mutex
	pending *udpStandalonePending
	expires time.Time
	readDeadline,writeDeadline time.Time
	changed chan struct{}
	terminal error
}

func newUDPStandaloneConn(raw net.Conn,cfg *udpHeaderConfig)*udpStandaloneConn{
	return &udpStandaloneConn{
		Conn:raw,config:cfg,closed:make(chan struct{}),
		queue:make(chan []byte,udpStandaloneQueue),changed:make(chan struct{}),
	}
}

func(c *udpStandaloneConn)ensureReader(){
	c.start.Do(func(){go c.reader()})
}

func(c *udpStandaloneConn)terminate(err error){
	c.closeOnce.Do(func(){
		c.mu.Lock()
		c.terminal=err
		close(c.closed)
		c.mu.Unlock()
		_ = c.Conn.Close()
	})
}
func(c *udpStandaloneConn)Close()error{
	c.terminate(net.ErrClosed)
	return nil
}
func(c *udpStandaloneConn)err()error{
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal!=nil{return c.terminal}
	return net.ErrClosed
}

func(c *udpStandaloneConn)reader(){
	var buf [udpWireLimit+1]byte
	for{
		n,err:=c.Conn.Read(buf[:])
		if err!=nil{c.terminate(err);return}
		if n>udpWireLimit{continue}
		c.mu.Lock()
		p:=c.pending
		if p!=nil&&n==c.config.receiveSize&&standaloneMatch(c.config.server,buf[:n],p.vars){
			c.expires=time.Now().Add(udpHeaderStateTTL)
			c.pending=nil
			close(p.done)
			c.mu.Unlock()
			continue
		}
		c.mu.Unlock()
		// Copy only when there is room; the only producer is this reader.
		if len(c.queue)<cap(c.queue){
			select{
			case <-c.closed:return
			case c.queue<-bytes.Clone(buf[:n]):
			default:
			}
		}
	}
}

func standaloneMatch(items []headerItem,wire []byte,initial map[string][]byte)bool{
	vars:=make(map[string][]byte,len(initial))
	for key,value:=range initial{vars[key]=value}
	off:=0
	for _,item:=range items{
		expected,err:=udpHeaderValue(item,vars,nil)
		if err!=nil{return false}
		size:=len(expected)+item.random
		if size>len(wire)-off{return false}
		b:=wire[off:off+size]
		if item.random==0&&!bytes.Equal(b,expected){return false}
		if item.capture!=""{vars[item.capture]=b}
		off+=size
	}
	return off==len(wire)
}

func(c *udpStandaloneConn)request()([]byte,map[string][]byte,error){
	vars:=make(map[string][]byte)
	var metadata map[string]uint64
	if c.config.needsMetadata{metadata=headerMetadata(c.Conn)}
	wire:=make([]byte,0,c.config.sendSize)
	for _,item:=range c.config.client{
		var b []byte
		var err error
		if item.random>0{b,err=headerRandom(item)}else{b,err=udpHeaderValue(item,vars,metadata)}
		if err!=nil{return nil,nil,err}
		if item.capture!=""{vars[item.capture]=bytes.Clone(b)}
		wire=append(wire,b...)
	}
	if len(wire)!=c.config.sendSize{return nil,nil,errors.New("standalone request width changed")}
	return wire,vars,nil
}

func(c *udpStandaloneConn)Write(p []byte)(int,error){
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select{case <-c.closed:return 0,c.err();default:}
	if len(p)>udpWireLimit{return 0,errors.New("standalone datagram too large")}
	c.ensureReader()
	c.mu.Lock()
	expired:=!time.Now().Before(c.expires)
	c.mu.Unlock()
	if expired{
		wire,vars,err:=c.request()
		if err!=nil{return 0,err}
		waiter:=&udpStandalonePending{vars:vars,done:make(chan struct{})}
		c.mu.Lock()
		c.pending=waiter
		c.mu.Unlock()
		n,err:=c.Conn.Write(wire)
		if err==nil&&n!=len(wire){err=io.ErrShortWrite}
		if err==nil{err=c.waitHandshake(waiter,time.Now().Add(headerTimeout))}
		if err!=nil{c.terminate(err);return 0,err}
	}
	n,err:=c.Conn.Write(p)
	if err==nil&&n!=len(p){err=io.ErrShortWrite}
	return n,err
}

func(c *udpStandaloneConn)waitHandshake(p *udpStandalonePending,limit time.Time)error{
	for{
		c.mu.Lock()
		deadline,changed:=c.writeDeadline,c.changed
		c.mu.Unlock()
		if deadline.IsZero()||limit.Before(deadline){deadline=limit}
		if !time.Now().Before(deadline){return os.ErrDeadlineExceeded}
		t:=time.NewTimer(time.Until(deadline))
		select{
		case <-p.done:t.Stop();return nil
		case <-c.closed:t.Stop();return c.err()
		case <-changed:t.Stop()
		case <-t.C:
		}
	}
}

// The read pump must not inherit caller read deadlines: a deadline is
// recoverable for Read, not a fatal shutdown of the underlying transport.
func(c *udpStandaloneConn)SetReadDeadline(t time.Time)error{
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline=t
	c.notify()
	return nil
}
func(c *udpStandaloneConn)SetWriteDeadline(t time.Time)error{
	c.mu.Lock()
	defer c.mu.Unlock()
	if err:=c.Conn.SetWriteDeadline(t);err!=nil{return err}
	c.writeDeadline=t
	c.notify()
	return nil
}
func(c *udpStandaloneConn)SetDeadline(t time.Time)error{
	c.mu.Lock()
	defer c.mu.Unlock()
	if err:=c.Conn.SetWriteDeadline(t);err!=nil{return err}
	c.readDeadline,c.writeDeadline=t,t
	c.notify()
	return nil
}
func(c *udpStandaloneConn)notify(){
	close(c.changed)
	c.changed=make(chan struct{})
}

func(c *udpStandaloneConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.ensureReader()
	for{
		c.mu.Lock()
		deadline,changed:=c.readDeadline,c.changed
		c.mu.Unlock()
		var timer *time.Timer
		var timeout <-chan time.Time
		if !deadline.IsZero(){
			if !time.Now().Before(deadline){return 0,os.ErrDeadlineExceeded}
			timer=time.NewTimer(time.Until(deadline));timeout=timer.C
		}
		select{
		case b:=<-c.queue:
			if timer!=nil{timer.Stop()}
			return copy(p,b),nil
		case <-c.closed:
			if timer!=nil{timer.Stop()}
			return 0,c.err()
		case <-changed:
			if timer!=nil{timer.Stop()}
		case <-timeout:
		}
	}
}
