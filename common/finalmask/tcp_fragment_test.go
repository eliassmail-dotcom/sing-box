package finalmask

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

type capture struct {
	net.Conn
	writes [][]byte
	short bool
}
func (c *capture) Write(p []byte) (int,error) {
	if c.short { return len(p)-1,nil }
	c.writes = append(c.writes, bytes.Clone(p))
	return len(p),nil
}
func config(t *testing.T, o option.LXFinalMaskFragmentOptions) *TCPFragment {
	t.Helper()
	f,err:=NewTCPFragment(&o)
	if err!=nil { t.Fatal(err) }
	return f
}
func TestLXFinalMaskTCPRange(t *testing.T) {
	f:=config(t,option.LXFinalMaskFragmentOptions{Packets:"2-3",Lengths:[]string{"2","3"},MaxSplit:"3"})
	raw:=&capture{}
	c:=f.Wrap(raw)
	for _,s:=range []string{"first","abcdefghij","12345678","last"} {
		if n,err:=c.Write([]byte(s));err!=nil||n!=len(s){t.Fatalf("write %d %v",n,err)}
	}
	want:=[][]byte{[]byte("first"),[]byte("ab"),[]byte("cde"),[]byte("fghij"),[]byte("12"),[]byte("345"),[]byte("678"),[]byte("last")}
	if !reflect.DeepEqual(raw.writes,want){t.Fatalf("got %q want %q",raw.writes,want)}
}
func TestLXFinalMaskTCPAllAndSingle(t *testing.T) {
	for _,packets:=range []string{"","1"} {
		f:=config(t,option.LXFinalMaskFragmentOptions{Packets:packets,Length:"2"})
		raw:=&capture{}
		c:=f.Wrap(raw)
		for i:=0;i<2;i++ {if _,err:=c.Write([]byte("abcde"));err!=nil{t.Fatal(err)}}
		want:=6
		if packets=="1"{want=4}
		if len(raw.writes)!=want||string(bytes.Join(raw.writes,nil))!="abcdeabcde"{t.Fatalf("got %q",raw.writes)}
	}
}
func TestLXFinalMaskTCPValidation(t *testing.T){
	for _,packets:=range []string{"tlshello","all","0","2-1","-1","1-2-3","2147483648"}{
		if _,err:=NewTCPFragment(&option.LXFinalMaskFragmentOptions{Packets:packets,Length:"2"});err==nil{t.Fatalf("accepted %q",packets)}
	}
}
func TestLXFinalMaskTCPBudgetAndShortWrite(t *testing.T){
	for _,o:=range []option.LXFinalMaskFragmentOptions{{Length:"1",Delay:"3000"},{Length:"1"}}{
		f:=config(t,o)
		raw:=&capture{}
		if n,err:=f.Wrap(raw).Write(make([]byte,maxSegments+1));err==nil||n!=0||len(raw.writes)!=0{t.Fatal("expected rejection before writing")}
	}
	f:=config(t,option.LXFinalMaskFragmentOptions{Length:"4"})
	if n,err:=f.Wrap(&capture{short:true}).Write([]byte("abcdefgh"));n!=3||!errors.Is(err,io.ErrShortWrite){t.Fatalf("got %d %v",n,err)}
}
func TestLXFinalMaskTCPConcurrentWrites(t *testing.T){
	f:=config(t,option.LXFinalMaskFragmentOptions{Length:"2"})
	raw:=&capture{}
	c:=f.Wrap(raw)
	var wg sync.WaitGroup
	for _,s:=range []string{"aaaaaaaa","bbbbbbbb"}{
		wg.Add(1)
		go func(s string){defer wg.Done();if _,err:=c.Write([]byte(s));err!=nil{t.Error(err)}}(s)
	}
	wg.Wait()
	got:=string(bytes.Join(raw.writes,nil))
	if got!="aaaaaaaabbbbbbbb"&&got!="bbbbbbbbaaaaaaaa"{t.Fatalf("interleaved: %s",got)}
}
func TestLXFinalMaskTCPInterrupt(t *testing.T){
	for _,tc:=range []struct{name string; interrupt func(net.Conn)error; want error}{
		{"close",func(c net.Conn)error{return c.Close()},net.ErrClosed},
		{"deadline",func(c net.Conn)error{return c.SetWriteDeadline(time.Now().Add(-time.Millisecond))},os.ErrDeadlineExceeded},
	}{
		t.Run(tc.name,func(t *testing.T){
			raw,peer:=net.Pipe()
			defer raw.Close();defer peer.Close()
			peer.SetReadDeadline(time.Now().Add(time.Second))
			f:=config(t,option.LXFinalMaskFragmentOptions{Length:"2",Delay:"2000"})
			c:=f.Wrap(raw)
			type result struct{n int;err error}
			done:=make(chan result,1)
			go func(){n,err:=c.Write([]byte("abcd"));done<-result{n,err}}()
			if _,err:=io.ReadFull(peer,make([]byte,2));err!=nil{t.Fatal(err)}
			if err:=tc.interrupt(c);err!=nil{t.Fatal(err)}
			select{
			case r:=<-done:if r.n!=2||!errors.Is(r.err,tc.want){t.Fatalf("got %d %v",r.n,r.err)}
			case <-time.After(time.Second):t.Fatal("wait not interrupted")
			}
		})
	}
}
