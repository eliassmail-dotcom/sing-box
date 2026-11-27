package finalmask

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/dns/dnsmessage"
)

const xdnsMultiDialTimeout=2*time.Second

type xdnsResolverSlot struct{
	conn net.Conn
	dead bool
	unanswered uint32
	pending [64]xdnsPending
	next int
}

type xdnsMultiConn struct{
	slots []xdnsResolverSlot
	remote net.Addr
	closed chan struct{}
	queue chan []byte
	start,closeOnce sync.Once
	mu,writeMu sync.Mutex
	cursor int
	readDeadline,writeDeadline time.Time
	changed chan struct{}
}

func newXDNSMultiConn(ctx context.Context,dialer N.Dialer,cfg *xdnsConfig)(net.Conn,error){
	c:=&xdnsMultiConn{
		remote:&net.UDPAddr{IP:net.IP(cfg.resolver.Addr.AsSlice()),Port:int(cfg.resolver.Port)},
		closed:make(chan struct{}),queue:make(chan []byte,8),changed:make(chan struct{}),
	}
	for _,r:=range append([]*xdnsConfig{cfg},cfg.alternates...){
		if ctx.Err()!=nil{c.Close();return nil,ctx.Err()}
		var conn net.Conn
		if r.network=="https"{conn=newXDNSDoHConn(ctx,dialer,r)}else{
			dialCtx,cancel:=context.WithTimeout(ctx,xdnsMultiDialTimeout)
			raw,err:=dialer.DialContext(dialCtx,r.network,r.resolver)
			cancel()
			if err!=nil{continue}
			conn=raw
			if r.network=="tcp"{conn=newXDNSTCPConn(raw)}
		}
		c.slots=append(c.slots,xdnsResolverSlot{conn:conn})
	}
	if len(c.slots)==0{c.Close();return nil,errors.New("all XDNS resolver dials failed")}
	if ctx.Err()!=nil{c.Close();return nil,ctx.Err()}
	return c,nil
}

func(c *xdnsMultiConn)ensure(){
	c.start.Do(func(){
		for i:=range c.slots{go c.reader(i)}
	})
}
func(c *xdnsMultiConn)Close()error{
	c.closeOnce.Do(func(){
		close(c.closed)
		for i:=range c.slots{_ = c.slots[i].conn.Close()}
	})
	return nil
}
func(c *xdnsMultiConn)retire(i int){
	c.mu.Lock()
	c.slots[i].dead=true
	live:=false
	for j:=range c.slots{if !c.slots[j].dead{live=true;break}}
	c.mu.Unlock()
	_ = c.slots[i].conn.Close()
	if !live{c.Close()}
}

func(c *xdnsMultiConn)reader(i int){
	var buf [4097]byte
	for{
		n,err:=c.slots[i].conn.Read(buf[:])
		if err!=nil{c.retire(i);return}
		if n>4096{continue}
		var msg dnsmessage.Message
		if msg.Unpack(buf[:n])!=nil||!msg.Header.Response||msg.Header.Truncated||msg.Header.RCode!=dnsmessage.RCodeSuccess||len(msg.Questions)!=1{continue}
		q:=msg.Questions[0]
		if q.Class!=dnsmessage.ClassINET{continue}
		now:=time.Now()
		c.mu.Lock()
		slot:=&c.slots[i]
		matched:=false
		for j,p:=range slot.pending{
			if p.name!=""&&p.id==msg.Header.ID&&p.typ==q.Type&&strings.EqualFold(p.name,q.Name.String())&&now.Before(p.until){
				slot.pending[j]=xdnsPending{}
				slot.unanswered=0
				matched=true
				break
			}
		}
		c.mu.Unlock()
		if !matched{continue}
		b:=bytes.Clone(buf[:n])
		select{case <-c.closed:return;case c.queue<-b:default:}
	}
}

func(c *xdnsMultiConn)choose()int{
	best:=-1
	for j:=range c.slots{
		i:=(c.cursor+j)%len(c.slots)
		s:=&c.slots[i]
		if s.dead{continue}
		if best<0||s.unanswered<c.slots[best].unanswered{best=i}
	}
	if best>=0{c.cursor=(best+1)%len(c.slots)}
	return best
}

func(c *xdnsMultiConn)Write(p []byte)(int,error){
	if len(p)<12||len(p)>4096{return 0,errors.New("invalid XDNS multi query size")}
	var msg dnsmessage.Message
	if msg.Unpack(p)!=nil||msg.Header.Response||len(msg.Questions)!=1{return 0,errors.New("invalid XDNS multi query")}
	c.ensure()
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	for{
		select{case <-c.closed:return 0,net.ErrClosed;default:}
		c.mu.Lock()
		if !c.writeDeadline.IsZero()&&!time.Now().Before(c.writeDeadline){c.mu.Unlock();return 0,os.ErrDeadlineExceeded}
		i:=c.choose()
		if i<0{c.mu.Unlock();return 0,net.ErrClosed}
		s:=&c.slots[i]
		if s.unanswered<^uint32(0){s.unanswered++}
		s.pending[s.next%len(s.pending)]=xdnsPending{id:msg.Header.ID,typ:msg.Questions[0].Type,name:msg.Questions[0].Name.String(),until:time.Now().Add(10*time.Second)}
		s.next++
		conn:=s.conn
		c.mu.Unlock()
		n,err:=conn.Write(p)
		if err==nil&&n==len(p){return n,nil}
		if err==nil{err=io.ErrShortWrite}
		// A timed-out write need not be a permanent resolver failure.
		c.mu.Lock();expired:=!c.writeDeadline.IsZero()&&!time.Now().Before(c.writeDeadline);c.mu.Unlock()
		if expired{return 0,err}
		c.retire(i)
	}
}
func(c *xdnsMultiConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.ensure()
	for{
		select{case <-c.closed:return 0,net.ErrClosed;default:}
		c.mu.Lock();deadline,changed:=c.readDeadline,c.changed;c.mu.Unlock()
		timer,timeout,err:=dohTimer(deadline)
		if err!=nil{return 0,err}
		select{
		case <-c.closed:if timer!=nil{timer.Stop()};return 0,net.ErrClosed
		case b:=<-c.queue:if timer!=nil{timer.Stop()};return copy(p,b),nil
		case <-changed:
		case <-timeout:
		}
		if timer!=nil{timer.Stop()}
	}
}
func(c *xdnsMultiConn)setDeadline(t time.Time,read,write bool)error{
	c.mu.Lock()
	defer c.mu.Unlock()
	if read{c.readDeadline=t}
	if write{
		c.writeDeadline=t
		for i:=range c.slots{if !c.slots[i].dead{_ = c.slots[i].conn.SetWriteDeadline(t)}}
	}
	close(c.changed);c.changed=make(chan struct{})
	return nil
}
func(c *xdnsMultiConn)SetDeadline(t time.Time)error{return c.setDeadline(t,true,true)}
func(c *xdnsMultiConn)SetReadDeadline(t time.Time)error{return c.setDeadline(t,true,false)}
func(c *xdnsMultiConn)SetWriteDeadline(t time.Time)error{return c.setDeadline(t,false,true)}
func(c *xdnsMultiConn)LocalAddr()net.Addr{return &net.UDPAddr{IP:net.IPv4zero}}
func(c *xdnsMultiConn)RemoteAddr()net.Addr{return c.remote}
