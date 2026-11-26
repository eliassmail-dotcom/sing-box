package finalmask

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)
func TestLXFinalMaskHeaderTransformOps(t *testing.T){
	cases:=[]struct{json,want string}{
		{`{"op":"concat","args":[{"reuse":"v"},{"bytes":[4]}]}`,"01020304"},
		{`{"op":"slice","args":[{"reuse":"v"},{"u64":1},{"u64":2}]}`,"0203"},
		{`{"op":"truncate","args":[{"reuse":"v"},{"u64":2}]}`,"0102"},
		{`{"op":"pad","args":[{"reuse":"v"},{"u64":6},{"bytes":[9,8]}]}`,"010203090809"},
		{`{"op":"be16","args":[{"transform":{"op":"xor16","args":[{"u64":4660},{"u64":255}]}}]}`,"12cb"},
		{`{"op":"le16","args":[{"u64":4660}]}`,"3412"},
		{`{"op":"be32","args":[{"transform":{"op":"xor32","args":[{"u64":4294967295},{"u64":255}]}}]}`,"ffffff00"},
		{`{"op":"le32","args":[{"u64":16909060}]}`,"04030201"},
		{`{"op":"le64","args":[{"transform":{"op":"add","args":[{"u64":1},{"u64":2}]}}]}`,"0300000000000000"},
		{`{"op":"be16","args":[{"transform":{"op":"sub","args":[{"u64":10},{"u64":3}]}}]}`,"0007"},
		{`{"op":"be16","args":[{"transform":{"op":"and","args":[{"u64":15},{"u64":6}]}}]}`,"0006"},
		{`{"op":"be16","args":[{"transform":{"op":"or","args":[{"u64":8},{"u64":3}]}}]}`,"000b"},
		{`{"op":"be16","args":[{"transform":{"op":"shl","args":[{"u64":3},{"u64":4}]}}]}`,"0030"},
		{`{"op":"be16","args":[{"transform":{"op":"shr","args":[{"u64":48},{"u64":4}]}}]}`,"0003"},
		{`{"op":"be16","args":[{"metadata":"remote_port"}]}`,"01bb"},
	}
	for _,tc:=range cases{
		c:=headerExprCompiler{sizes:map[string]int{"v":3}}
		e,err:=c.compile(json.RawMessage(tc.json),0);if err!=nil{t.Fatal(err)}
		v,err:=e.eval(map[string][]byte{"v":{1,2,3}},map[string]uint64{"remote_port":443})
		if err!=nil||hex.EncodeToString(v.b)!=tc.want||len(v.b)!=e.width{t.Fatalf("%s got %x %v want %s",tc.json,v.b,err,tc.want)}
	}
}

func TestLXFinalMaskHeaderTransformReject(t *testing.T){
	for _,s:=range []string{
		`{"op":"slice","args":[{"bytes":[1]},{"u64":18446744073709551615},{"u64":1}]}`,
		`{"op":"pad","args":[{"bytes":[1]},{"u64":16385},{"bytes":[0]}]}`,
		`{"op":"concat","args":[{"reuse":"future"}]}`,
		`{"op":"be16","args":[{"bytes":[1]}]}`,
		`{"op":"be16","args":[{"u64":1,"reuse":"v"}]}`,
		`{"op":"be16","args":[{"u64":1,"typo":1}]}`,
		`{"op":"be16","args":[{"metadata":"unknown"}]}`,
	}{
		c:=headerExprCompiler{sizes:map[string]int{"v":1}}
		if _,err:=c.compile(json.RawMessage(s),0);err==nil{t.Fatalf("accepted %s",s)}
	}
	for _,s:=range []string{
		`{"op":"be16","args":[{"u64":65536}]}`,
		`{"op":"le64","args":[{"transform":{"op":"add","args":[{"u64":18446744073709551615},{"u64":1}]}}]}`,
		`{"op":"le64","args":[{"transform":{"op":"shl","args":[{"u64":1},{"u64":64}]}}]}`,
		`{"op":"le64","args":[{"transform":{"op":"sub","args":[{"u64":0},{"u64":1}]}}]}`,
		`{"op":"be16","args":[{"metadata":"remote_port"}]}`,
	}{
		c:=headerExprCompiler{}
		e,err:=c.compile(json.RawMessage(s),0);if err!=nil{t.Fatal(err)}
		if _,err:=e.eval(nil,nil);err==nil{t.Fatalf("accepted runtime %s",s)}
	}
	deep:=`{"op":"be16","args":[{"u64":1}]}`
	for i:=0;i<14;i++{deep=`{"op":"concat","args":[{"transform":`+deep+`}]}`}
	c:=headerExprCompiler{}
	if _,err:=c.compile(json.RawMessage(deep),0);err==nil{t.Fatal("accepted deep expression")}
}
func TestLXFinalMaskHeaderTransformExchange(t *testing.T){
	h:=headerConfig(t,`{"clients":[[{"packet":[1,2,3],"capture":"v"}],[{"transform":{"op":"concat","args":[{"reuse":"s"},{"bytes":[9]}]},"capture":"echo"}]],"servers":[[{"rand":2,"capture":"s"}],[{"transform":{"op":"slice","args":[{"reuse":"echo"},{"u64":1},{"u64":2}]}}]]}`)
	client,peer:=net.Pipe()
	defer client.Close();defer peer.Close()
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second);defer cancel()
	done:=make(chan error,1)
	go func(){
		peer.SetDeadline(time.Now().Add(time.Second))
		b:=make([]byte,3)
		if _,err:=io.ReadFull(peer,b);err!=nil{done<-err;return}
		if _,err:=peer.Write([]byte{7,8});err!=nil{done<-err;return}
		if _,err:=io.ReadFull(peer,b);err!=nil{done<-err;return}
		if hex.EncodeToString(b)!="070809"{done<-io.ErrUnexpectedEOF;return}
		_,err:=peer.Write([]byte{8,9});done<-err
	}()
	if _,err:=h.Handshake(ctx,client);err!=nil{t.Fatal(err)}
	if err:=<-done;err!=nil{t.Fatal(err)}
}
func TestLXFinalMaskHeaderTransformWireBudget(t *testing.T){
	c:=headerExprCompiler{sizes:map[string]int{"v":16384}}
	_,err:=c.compile(json.RawMessage(`{"op":"concat","args":[{"reuse":"v"},{"bytes":[1]}]}`),0)
	if err==nil||!strings.Contains(err.Error(),"concat"){t.Fatalf("got %v",err)}
}
