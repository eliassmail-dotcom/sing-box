package sudoku

import (
	"errors"
	"io"
	"net"
	"sync"
)

const chunkSize=4096

type decoder interface{
	decodeChunk([]byte,[]byte)([]byte,error)
	reset()
}
type hintDecoder struct{
	tables []*table
	index int
	hints []byte
}
func(d *hintDecoder)decodeChunk(in,pending []byte)([]byte,error){
	var err error
	d.hints,pending,err=decodeBytes(d.tables,&d.index,in,d.hints,pending)
	return pending,err
}
func(d *hintDecoder)reset(){d.hints=nil}

// The stream is transformed for its whole lifetime. Do not expose upstream
// or splice interfaces. Allocation is bounded per operation.
type maskedConn struct{
	net.Conn
	enc func([]byte)([]byte,error)
	dec decoder
	rmu,wmu sync.Mutex
	pending []byte
	readErr,writeErr error
}
func newConn(c net.Conn,enc func([]byte)([]byte,error),dec decoder)net.Conn{
	return &maskedConn{Conn:c,enc:enc,dec:dec}
}
func(c *maskedConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.rmu.Lock();defer c.rmu.Unlock()
	var raw [chunkSize]byte
	for len(c.pending)==0 {
		if c.readErr!=nil{
			err:=c.readErr
			// Socket deadlines are recoverable. Preserve decoder state and
			// deliver the timeout once, allowing a later deadline reset.
			if ne,ok:=err.(net.Error);ok&&ne.Timeout(){c.readErr=nil}
			return 0,err
		}
		n,err:=c.Conn.Read(raw[:])
		if n>0{
			out,decodeErr:=c.dec.decodeChunk(raw[:n],c.pending[:0])
			if decodeErr!=nil{c.readErr=decodeErr;return 0,decodeErr}
			c.pending=out
		}
		if err!=nil{
			c.readErr=err
			if errors.Is(err,io.EOF){c.dec.reset()}
		}
		if n==0&&err==nil{return 0,io.ErrNoProgress}
	}
	n:=copy(p,c.pending)
	copy(c.pending,c.pending[n:])
	c.pending=c.pending[:len(c.pending)-n]
	return n,nil
}
func(c *maskedConn)Write(p []byte)(int,error){
	c.wmu.Lock();defer c.wmu.Unlock()
	if c.writeErr!=nil{return 0,c.writeErr}
	total:=0
	for len(p)>0{
		n:=min(len(p),chunkSize)
		wire,err:=c.enc(p[:n])
		if err==nil{
			for len(wire)>0{
				k,e:=c.Conn.Write(wire)
				if e!=nil{err=e;break}
				if k<=0||k>len(wire){err=io.ErrShortWrite;break}
				wire=wire[k:]
			}
		}
		if err!=nil{
			// A partial encoded chunk cannot be retried at the plaintext
			// boundary. Close and make the failure sticky.
			c.writeErr=err
			_ = c.Conn.Close()
			return total,err
		}
		total+=n;p=p[n:]
	}
	return total,nil
}
func(c *maskedConn)CloseWrite()error{
	c.wmu.Lock();defer c.wmu.Unlock()
	if raw,ok:=c.Conn.(interface{CloseWrite()error});ok{return raw.CloseWrite()}
	return net.ErrClosed
}
