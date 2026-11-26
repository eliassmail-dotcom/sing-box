package sudoku

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestLXFinalMaskSudokuRoundTrip(t *testing.T){
	for _,config:=range []Config{
		{Password:"test",Ascii:"prefer_ascii"},
		{Password:"test",Ascii:"prefer_entropy",PaddingMin:100,PaddingMax:100},
		{Password:"test",CustomTables:[]string{"xpxvvpvv","vxpvxvvp"},PaddingMin:20,PaddingMax:40},
	}{
		m,err:=New(&config);if err!=nil{t.Fatal(err)}
		raw,peer:=net.Pipe()
		client,server:=m.WrapClient(raw),m.WrapServer(peer)
		client.SetDeadline(time.Now().Add(5*time.Second))
		server.SetDeadline(time.Now().Add(5*time.Second))
		payload:=make([]byte,10001)
		for i:=range payload{payload[i]=byte(i)}
		done:=make(chan error,1)
		go func(){buf:=make([]byte,len(payload));_,err:=io.ReadFull(server,buf);if err==nil&&!bytes.Equal(buf,payload){err=io.ErrUnexpectedEOF};if err==nil{_,err=server.Write(buf)};done<-err}()
		if n,err:=client.Write(payload);err!=nil||n!=len(payload){t.Fatalf("write %d %v",n,err)}
		buf:=make([]byte,len(payload))
		if _,err:=io.ReadFull(client,buf);err!=nil||!bytes.Equal(buf,payload){t.Fatalf("roundtrip %v",err)}
		if err:=<-done;err!=nil{t.Fatal(err)}
		client.Close();server.Close()
	}
}

func TestLXFinalMaskSudokuSharedClues(t *testing.T){
	m,err:=New(&Config{Password:"test",Ascii:"prefer_ascii"});if err!=nil{t.Fatal(err)}
	m2,err:=New(&Config{Password:"test",Ascii:"prefer_entropy"});if err!=nil{t.Fatal(err)}
	for i:=0;i<256;i++{
		if &m.tables[0].encode[i][0]!=&m2.tables[0].encode[i][0]{t.Fatal("clues duplicated")}
		// Every original clue tuple must decode in every layout.
		for _,tab:=range []*table{m.tables[0],m2.tables[0]}{
			for _,group:=range tab.encode[i]{
				wire:=make([]byte,4);for j,v:=range group{wire[j]=tab.layout.encodeHint(v)}
				idx:=0
				_,out,err:=decodeBytes([]*table{tab},&idx,wire,nil,nil)
				if err!=nil||len(out)!=1||out[0]!=byte(i){t.Fatalf("byte %d decode %v %v",i,out,err)}
			}
		}
	}
}

func TestLXFinalMaskSudokuPackedReference(t *testing.T){
	m,err:=New(&Config{Ascii:"prefer_ascii"});if err!=nil{t.Fatal(err)}
	// 0x41 = groups 16,16; ASCII layout maps them to 0x50,0x50.
	// The 0x3f padding marker discards residual bits before the next write.
	d:=&packedStreamDecoder{layouts:tablesToLayouts(m.tables)}
	out,err:=d.decodeChunk([]byte{0x50,0x50,0x3f,0x50,0x60,0x3f},nil)
	if err!=nil||string(out)!="AB"{t.Fatalf("packed vector %q %v",out,err)}
}

func TestLXFinalMaskSudokuValidation(t *testing.T){
	for _,c:=range []Config{{Ascii:"invalid"},{CustomTable:"invalid"},{CustomTables:make([]string,9)},{PaddingMax:101}}{
		if _,err:=New(&c);err==nil{t.Fatalf("accepted invalid config %+v",c)}
	}
}
