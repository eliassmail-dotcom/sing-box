package finalmask

import (
	"bytes"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func standaloneFixture(t *testing.T)(*udpStandaloneConn,*net.UDPConn){
	t.Helper()
	m,err:=NewUDPChain(udpHeaderOpts(`{"mode":"standalone","client":[{"packet":[1]},{"rand":2,"randRange":7,"capture":"v"}],"server":[{"packet":[9]},{"reuse":"v"}]}`))
	if err!=nil{t.Fatal(err)}
	peer,err:=net.ListenUDP("udp",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
	if err!=nil{t.Fatal(err)}
	raw,err:=net.DialUDP("udp",nil,peer.LocalAddr().(*net.UDPAddr))
	if err!=nil{peer.Close();t.Fatal(err)}
	c:=m.WrapConnected(raw).(*udpStandaloneConn)
	t.Cleanup(func(){c.Close();peer.Close()})
	peer.SetDeadline(time.Now().Add(2*time.Second))
	c.SetDeadline(time.Now().Add(2*time.Second))
	return c,peer
}

func TestLXFinalMaskUDPStandaloneExchange(t *testing.T){
	c,peer:=standaloneFixture(t)
	for i:=0;i<2;i++{
		if i==1{c.mu.Lock();c.expires=time.Now().Add(-time.Second);c.mu.Unlock()}
		read:=make(chan error,1)
		go func(){
			buf:=make([]byte,16)
			n,e:=c.Read(buf)
			if e==nil&&!bytes.Equal(buf[:n],[]byte("reply")){e=errors.New("bad reply")}
			read<-e
		}()
		written:=make(chan error,1)
		go func(){_,e:=c.Write([]byte("data"));written<-e}()
		b:=make([]byte,16)
		n,addr,e:=peer.ReadFromUDP(b)
		if e!=nil||!bytes.Equal(b[:n],[]byte{1,7,7}){t.Fatalf("request %x %v",b[:n],e)}
		if _,e:=peer.WriteToUDP([]byte{9,7,7},addr);e!=nil{t.Fatal(e)}
		n,_,e=peer.ReadFromUDP(b)
		if e!=nil||string(b[:n])!="data"{t.Fatalf("payload %q %v",b[:n],e)}
		if _,e:=peer.WriteToUDP([]byte("reply"),addr);e!=nil{t.Fatal(e)}
		if e:=<-written;e!=nil{t.Fatal(e)}
		if e:=<-read;e!=nil{t.Fatal(e)}
	}
}
func TestLXFinalMaskUDPStandaloneDeadlineAndClose(t *testing.T){
	c,peer:=standaloneFixture(t)
	c.SetReadDeadline(time.Now().Add(20*time.Millisecond))
	if _,e:=c.Read(make([]byte,1));!errors.Is(e,os.ErrDeadlineExceeded){t.Fatalf("read deadline: %v",e)}
	c.SetReadDeadline(time.Time{})
	done:=make(chan error,1)
	go func(){_,e:=c.Write([]byte("data"));done<-e}()
	if _,_,e:=peer.ReadFromUDP(make([]byte,16));e!=nil{t.Fatal(e)}
	c.SetWriteDeadline(time.Now().Add(-time.Millisecond))
	select{
	case e:=<-done:if !errors.Is(e,os.ErrDeadlineExceeded){t.Fatalf("write deadline: %v",e)}
	case <-time.After(time.Second):t.Fatal("handshake not interrupted")
	}
	if _,e:=c.Read(make([]byte,1));!errors.Is(e,os.ErrDeadlineExceeded){t.Fatalf("terminal read: %v",e)}
}
func TestLXFinalMaskUDPStandaloneQueueBound(t *testing.T){
	c,peer:=standaloneFixture(t)
	done:=make(chan error,1)
	go func(){_,e:=c.Write([]byte("data"));done<-e}()
	b:=make([]byte,16)
	_,addr,e:=peer.ReadFromUDP(b)
	if e!=nil{t.Fatal(e)}
	for i:=0;i<udpStandaloneQueue+8;i++{if _,e:=peer.WriteToUDP([]byte{4},addr);e!=nil{t.Fatal(e)}}
	if _,e:=peer.WriteToUDP([]byte{9,7,7},addr);e!=nil{t.Fatal(e)}
	if n,_,e:=peer.ReadFromUDP(b);e!=nil||string(b[:n])!="data"{t.Fatalf("handshake blocked by queue: %v",e)}
	if e:=<-done;e!=nil{t.Fatal(e)}
	if len(c.queue)>udpStandaloneQueue{t.Fatal("queue overflow")}
}
func TestLXFinalMaskUDPStandaloneGuard(t *testing.T){
	opts:=udpHeaderOpts(`{"mode":"standalone","client":[{"packet":[1]}],"server":[{"packet":[2]}]}`)
	if _,e:=NewUDPChain(append(opts,udpOpts(`{"password":"test-key"}`)[0]));e==nil{t.Fatal("unvalidated combination")}
	if _,e:=NewUDPChain([]option.LXFinalMaskUDPMaskOptions{opts[0]});e!=nil{t.Fatal(e)}
}
