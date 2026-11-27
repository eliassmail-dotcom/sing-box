package finalmask

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type hopPath struct{
	conn net.PacketConn
	target M.Socksaddr
	oldTarget M.Socksaddr
}
type udpHopConn struct{
	ctx context.Context
	cancel context.CancelFunc
	dialer N.Dialer
	cfg *udpHopConfig
	server M.Socksaddr
	mu,hopMu sync.Mutex
	current,previous *hopPath
	queue chan []byte
	closed chan struct{}
	closeOnce sync.Once
	changed chan struct{}
	readDeadline,writeDeadline time.Time
}

func dialUDPHop(ctx context.Context,dialer N.Dialer,server M.Socksaddr,cfg *udpHopConfig)(net.Conn,error){
	if err:=cfg.validateServer(server);err!=nil{return nil,err}
	target:=server
	if cfg.remote||cfg.once{target=cfg.target(server)}
	if !cfg.local&&!cfg.remote{return dialer.DialContext(ctx,"udp",target)}
	raw,err:=dialer.ListenPacket(ctx,target)
	if err!=nil{return nil,err}
	if err=ctx.Err();err!=nil{raw.Close();return nil,err}
	life,cancel:=context.WithCancel(context.WithoutCancel(ctx))
	c:=&udpHopConn{ctx:life,cancel:cancel,dialer:dialer,cfg:cfg,server:server,current:&hopPath{conn:raw,target:target},queue:make(chan []byte,8),closed:make(chan struct{}),changed:make(chan struct{})}
	go c.reader(c.current)
	go c.loop()
	return c,nil
}
func(c *udpHopConn)loop(){
	t:=time.NewTimer(c.cfg.interval());defer t.Stop()
	for{
		select{
		case <-c.closed:return
		case <-t.C:c.hop();t.Reset(c.cfg.interval())
		}
	}
}
func(c *udpHopConn)hop(){
	c.hopMu.Lock();defer c.hopMu.Unlock()
	c.mu.Lock()
	if c.ctx.Err()!=nil{c.mu.Unlock();return}
	current:=c.current
	target:=current.target
	if c.cfg.remote{target=c.cfg.target(c.server)}
	if !c.cfg.local{
		current.oldTarget=current.target;current.target=target
		c.mu.Unlock();return
	}
	c.mu.Unlock()
	ctx,cancel:=context.WithTimeout(c.ctx,2*time.Second)
	raw,err:=c.dialer.ListenPacket(ctx,target)
	cancel()
	if err!=nil{return}
	c.mu.Lock()
	if c.ctx.Err()!=nil{c.mu.Unlock();raw.Close();return}
	if err=raw.SetWriteDeadline(c.writeDeadline);err!=nil{c.mu.Unlock();raw.Close();return}
	old:=c.previous
	c.previous=current
	next:=&hopPath{conn:raw,target:target}
	c.current=next
	c.mu.Unlock()
	if old!=nil{old.conn.Close()}
	go c.reader(next)
}
func(c *udpHopConn)reader(path *hopPath){
	var b [udpWireLimit+1]byte
	for{
		n,a,err:=path.conn.ReadFrom(b[:])
		if err!=nil{
			c.mu.Lock()
			active:=c.current==path&&c.ctx.Err()==nil
			c.mu.Unlock()
			if active{c.Close()}
			return
		}
		if n>udpWireLimit{continue}
		c.mu.Lock()
		ok:=(path==c.current||path==c.previous)&&(hopSameAddr(a,path.target)||hopSameAddr(a,path.oldTarget))
		c.mu.Unlock()
		if !ok{continue}
		select{case <-c.closed:return;default:}
		if len(c.queue)<cap(c.queue){
			select{case <-c.closed:return;case c.queue<-bytes.Clone(b[:n]):default:}
		}
	}
}
func(c *udpHopConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	for{
		c.mu.Lock();d,changed:=c.readDeadline,c.changed;c.mu.Unlock()
		if c.ctx.Err()!=nil{return 0,net.ErrClosed}
		timer,timeout,err:=dohTimer(d);if err!=nil{return 0,err}
		select{
		case <-c.closed:if timer!=nil{timer.Stop()};return 0,net.ErrClosed
		case b:=<-c.queue:if timer!=nil{timer.Stop()};return copy(p,b),nil
		case <-changed:
		case <-timeout:
		}
		if timer!=nil{timer.Stop()}
	}
}
func(c *udpHopConn)Write(p []byte)(int,error){
	if len(p)>udpWireLimit{return 0,errors.New("UDP Hop datagram too large")}
	c.mu.Lock()
	if c.ctx.Err()!=nil{c.mu.Unlock();return 0,net.ErrClosed}
	path,target,d:=c.current,c.current.target,c.writeDeadline
	c.mu.Unlock()
	if !d.IsZero()&&!time.Now().Before(d){return 0,os.ErrDeadlineExceeded}
	n,err:=path.conn.WriteTo(p,hopUDPAddr(target))
	if err==nil&&n!=len(p){err=io.ErrShortWrite}
	return n,err
}
func(c *udpHopConn)Close()error{
	c.closeOnce.Do(func(){
		c.cancel();close(c.closed)
		c.mu.Lock();cur,prev:=c.current,c.previous;c.mu.Unlock()
		if cur!=nil{cur.conn.Close()};if prev!=nil{prev.conn.Close()}
	})
	return nil
}
func(c *udpHopConn)LocalAddr()net.Addr{
	c.mu.Lock();defer c.mu.Unlock()
	return c.current.conn.LocalAddr()
}
func(c *udpHopConn)RemoteAddr()net.Addr{return hopUDPAddr(c.server)}
func(c *udpHopConn)setDeadline(t time.Time,read,write bool)error{
	c.mu.Lock();defer c.mu.Unlock()
	if c.ctx.Err()!=nil{return net.ErrClosed}
	if read{c.readDeadline=t}
	var err error
	if write{
		c.writeDeadline=t
		err=c.current.conn.SetWriteDeadline(t)
		if c.previous!=nil{_ = c.previous.conn.SetWriteDeadline(t)}
	}
	close(c.changed);c.changed=make(chan struct{})
	return err
}
func(c *udpHopConn)SetDeadline(t time.Time)error{return c.setDeadline(t,true,true)}
func(c *udpHopConn)SetReadDeadline(t time.Time)error{return c.setDeadline(t,true,false)}
func(c *udpHopConn)SetWriteDeadline(t time.Time)error{return c.setDeadline(t,false,true)}
