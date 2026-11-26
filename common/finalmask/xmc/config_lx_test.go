package xmc

import (
	"testing"
	"net"
	"io"
	"crypto/x509"
	"time"
)

func TestLXFinalMaskXMCConfigAndPeer(t *testing.T){
	o:=Config{Password:"test-password",Hostname:"localhost",Profiles:[]ProfileOptions{{Username:"Tester",UUID:"00112233-4455-6677-8899-aabbccddeeff",TexturesValue:"test-value",TexturesSignature:"test-signature"}}}
	m,err:=New(&o);if err!=nil{t.Fatal(err)}
	key,err:=DeriveRSAKey(o.Password);if err!=nil{t.Fatal(err)}
	client,peer:=net.Pipe()
	defer client.Close();defer peer.Close()
	c,err:=m.WrapClient(client);if err!=nil{t.Fatal(err)}
	defer c.Close()
	s,err:=wrapConnServer(peer,m.profiles,o.Password,x509.MarshalPKCS1PrivateKey(key),m.publicKey);if err!=nil{t.Fatal(err)}
	defer s.Close()
	c.SetDeadline(time.Now().Add(15*time.Second));s.SetDeadline(time.Now().Add(15*time.Second))
	done:=make(chan error,1)
	go func(){b:=make([]byte,4);_,e:=io.ReadFull(s,b);if e==nil&&string(b)!="ping"{e=io.ErrUnexpectedEOF};if e==nil{_,e=s.Write([]byte("pong"))};done<-e}()
	if _,err=c.Write([]byte("ping"));err!=nil{t.Fatal(err)}
	b:=make([]byte,4);if _,err=io.ReadFull(c,b);err!=nil||string(b)!="pong"{t.Fatalf("payload %q %v",b,err)}
	if err=<-done;err!=nil{t.Fatal(err)}
}
func TestLXFinalMaskXMCReject(t *testing.T){
	for _,o:=range []Config{{},{Password:"x"},{Password:"x",Profiles:[]ProfileOptions{{Username:"bad",UUID:"invalid",TexturesValue:"x",TexturesSignature:"y"}}}}{
		if _,err:=New(&o);err==nil{t.Fatal("accepted invalid XMC")}
	}
}
