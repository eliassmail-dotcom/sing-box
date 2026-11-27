package finalmask

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

func chainOptions(t *testing.T,s string)[]option.LXFinalMaskTCPMaskOptions{
	t.Helper()
	var opts []option.LXFinalMaskTCPMaskOptions
	if err:=json.Unmarshal([]byte(s),&opts);err!=nil{t.Fatal(err)}
	return opts
}

type recordConn struct{
	net.Conn
	mu sync.Mutex
	writes []string
}
func(c *recordConn)Write(p []byte)(int,error){
	c.mu.Lock()
	c.writes=append(c.writes,string(p))
	c.mu.Unlock()
	return c.Conn.Write(p)
}

func TestLXFinalMaskTCPChainOrder(t *testing.T){
	fragment:=`{"type":"fragment","settings":{"packets":"1","lengths":[2,"3"],"maxSplit":2}}`
	header:=`{"type":"header-custom","settings":{"clients":[[{"type":"str","packet":"HEAD"}]],"servers":[[{"type":"str","packet":"OK"}]]}}`
	for _,tc:=range []struct{name,config string;want []string}{
		{"header outer","["+header+","+fragment+"]",[]string{"HE","AD","data"}},
		{"fragment outer","["+fragment+","+header+"]",[]string{"HEAD","da","ta"}},
	}{
		t.Run(tc.name,func(t *testing.T){
			chain,err:=NewTCPChain(chainOptions(t,tc.config))
			if err!=nil{t.Fatal(err)}
			client,peer:=net.Pipe()
			defer client.Close();defer peer.Close()
			raw:=&recordConn{Conn:client}
			ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
			defer cancel()
			done:=make(chan error,1)
			go func(){
				peer.SetDeadline(time.Now().Add(time.Second))
				b:=make([]byte,4)
				if _,e:=io.ReadFull(peer,b);e!=nil||string(b)!="HEAD"{done<-errors.New("bad header");return}
				if _,e:=peer.Write([]byte("OK"));e!=nil{done<-e;return}
				if _,e:=io.ReadFull(peer,b);e!=nil||string(b)!="data"{done<-errors.New("bad payload");return}
				done<-nil
			}()
			c,err:=chain.Wrap(ctx,raw)
			if err!=nil{t.Fatal(err)}
			if _,err:=c.Write([]byte("data"));err!=nil{t.Fatal(err)}
			if err:=<-done;err!=nil{t.Fatal(err)}
			raw.mu.Lock()
			defer raw.mu.Unlock()
			if !reflect.DeepEqual(raw.writes,tc.want){t.Fatalf("writes %q want %q",raw.writes,tc.want)}
		})
	}
}

func TestLXFinalMaskTCPChainReject(t *testing.T){
	for _,s:=range []string{
		`[{"type":"unknown","settings":{}}]`,
		`[{"type":"fragment","settings":{"length":2,"typo":1}}]`,
		`[{"type":"fragment","settings":{"length":2,"maxSplit":1,"max_split":2}}]`,
		`[{"type":"fragment","settings":{"packets":"tlshello","length":2}}]`,
		`[{"type":"fragment","settings":{"length":null}}]`,
		`[{"type":"fragment","settings":{"length":2}},{"type":"fragment","settings":{"length":3}}]`,
		`[{"type":"header-custom","settings":{"clients":[[{"rand":1,"typo":1}]]}}]`,
		`[{"type":"header-custom","settings":null}]`,
	}{
		if _,err:=NewTCPChain(chainOptions(t,s));err==nil{t.Fatalf("accepted %s",s)}
	}
}

func TestLXFinalMaskTCPChainFailureCloses(t *testing.T){
	chain,err:=NewTCPChain(chainOptions(t,`[{"type":"header-custom","settings":{"clients":[[{"packet":[1]}]],"servers":[[{"packet":[2]}]]}},{"type":"fragment","settings":{"length":1}}]`))
	if err!=nil{t.Fatal(err)}
	raw,peer:=net.Pipe()
	defer raw.Close();defer peer.Close()
	peer.SetDeadline(time.Now().Add(time.Second))
	done:=make(chan error,1)
	go func(){
		if _,err:=io.ReadFull(peer,make([]byte,1));err!=nil{done<-err;return}
		if _,err:=peer.Write([]byte{3});err!=nil{done<-err;return}
		_,err:=peer.Read(make([]byte,1))
		done<-err
	}()
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
	defer cancel()
	c,err:=chain.Wrap(ctx,raw)
	if c!=nil||err==nil||!strings.Contains(err.Error(),"mismatch"){t.Fatalf("got %v %v",c,err)}
	if err:=<-done;!errors.Is(err,io.EOF){t.Fatalf("peer not closed: %v",err)}
}
