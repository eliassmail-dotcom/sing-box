package finalmask

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func headerConfig(t *testing.T,s string)*TCPHeader{
	t.Helper()
	var o option.LXFinalMaskTCPHeaderOptions
	if err:=json.Unmarshal([]byte(s),&o);err!=nil{t.Fatal(err)}
	h,err:=NewTCPHeader(&o)
	if err!=nil{t.Fatal(err)}
	return h
}

func TestLXFinalMaskTCPHeaderRoundTrip(t *testing.T){
	h:=headerConfig(t,`{"clients":[[{"type":"str","packet":"cli"},{"rand":2,"randRange":"16-32"}],[{"type":"hex","packet":"aa"}]],"servers":[[{"type":"base64","packet":"c3J2"},{"rand":1}],[{"packet":[9]}],[{"packet":[10]}]]}`)
	client,server:=net.Pipe()
	defer client.Close()
	defer server.Close()
	done:=make(chan error,1)
	go func(){
		server.SetDeadline(time.Now().Add(time.Second))
		buf:=make([]byte,5)
		if _,e:=io.ReadFull(server,buf);e!=nil{done<-e;return}
		if string(buf[:3])!="cli"||buf[3]<16||buf[3]>32||buf[4]<16||buf[4]>32{done<-errors.New("bad client bytes");return}
		if _,e:=server.Write([]byte{'s','r','v',0});e!=nil{done<-e;return}
		if _,e:=io.ReadFull(server,buf[:1]);e!=nil||buf[0]!=0xaa{done<-errors.New("bad second round");return}
		if _,e:=server.Write([]byte{9,10});e!=nil{done<-e;return}
		if _,e:=io.ReadFull(server,buf[:3]);e!=nil||string(buf[:3])!="app"{done<-errors.New("bad payload");return}
		_,e:=server.Write([]byte("ok"))
		done<-e
	}()
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
	defer cancel()
	c,err:=h.Handshake(ctx,client)
	if err!=nil{t.Fatal(err)}
	cancel() // cancellation after success must not close the stream.
	if _,err:=c.Write([]byte("app"));err!=nil{t.Fatal(err)}
	b:=make([]byte,2)
	if _,err:=io.ReadFull(c,b);err!=nil||string(b)!="ok"{t.Fatalf("payload %q %v",b,err)}
	if err:=<-done;err!=nil{t.Fatal(err)}
}

func TestLXFinalMaskTCPHeaderMismatchAndCancel(t *testing.T){
	h:=headerConfig(t,`{"clients":[[{"packet":[1]}]],"servers":[[{"packet":[2]}]]}`)
	for _,mismatch:=range []bool{true,false}{
		client,server:=net.Pipe()
		ctx,cancel:=context.WithTimeout(context.Background(),100*time.Millisecond)
		done:=make(chan error,1)
		go func(){
			b:=make([]byte,1)
			if _,e:=io.ReadFull(server,b);e!=nil{done<-e;return}
			if mismatch{_,e:=server.Write([]byte{3});done<-e;return}
			done<-nil
		}()
		c,err:=h.Handshake(ctx,client)
		cancel()
		server.Close()
		if c!=nil||err==nil{t.Fatal("expected closed failed handshake")}
		if mismatch&&!strings.Contains(err.Error(),"mismatch"){t.Fatal(err)}
		if !mismatch&&!errors.Is(err,context.DeadlineExceeded){t.Fatal(err)}
		if err:=<-done;err!=nil{t.Fatal(err)}
	}
}

func TestLXFinalMaskTCPHeaderValidation(t *testing.T){
	for _,s:=range []string{
		`{"clients":[[{"capture":"v","rand":2}]]}`,
		`{"clients":[[{"reuse":"v"}]]}`,
		`{"clients":[[{"transform":{"op":"xor"}}]]}`,
		`{"clients":[[{"rand":1,"packet":[1]}]]}`,
		`{"clients":[[{"rand":16385}]]}`,
		`{"clients":[[{"rand":1,"randRange":"9-2"}]]}`,
		`{"clients":[[{"rand":1,"delay":3000},{"rand":1,"delay":3000}]]}`,
		`{"errors":[[{"packet":[1]}]]}`,
	}{
		var o option.LXFinalMaskTCPHeaderOptions
		if err:=json.Unmarshal([]byte(s),&o);err!=nil{t.Fatal(err)}
		if _,err:=NewTCPHeader(&o);err==nil{t.Fatalf("accepted %s",s)}
	}
}
