package finalmask

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	mathrand "math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/option"
)

const (
	headerTimeout = 5*time.Second
	headerMaxBytes = 16384
	headerMaxItems = 256
)

type headerItem struct {
	packet []byte
	random int
	lo,hi int
	delayLo,delayHi int
}

type TCPHeader struct {
	clients,servers [][]headerItem
}

// headerRange accepts the numeric and string range forms used by Xray.
func headerRange(raw json.RawMessage, defLo,defHi,max int)(int,int,error){
	if len(raw)==0 {return defLo,defHi,nil}
	var value string
	if err:=json.Unmarshal(raw,&value);err!=nil {
		var n int
		if err:=json.Unmarshal(raw,&n);err!=nil{return 0,0,err}
		value=strconv.Itoa(n)
	}
	parts:=strings.Split(value,"-")
	if len(parts)>2{return 0,0,errors.New("invalid range")}
	lo,err:=strconv.Atoi(parts[0])
	if err!=nil{return 0,0,err}
	hi:=lo
	if len(parts)==2 {hi,err=strconv.Atoi(parts[1])}
	if err!=nil||lo<0||hi<lo||hi>max{return 0,0,errors.New("invalid range bounds")}
	return lo,hi,nil
}

func headerBytes(raw json.RawMessage,typ string)([]byte,error){
	if len(raw)==0 {return nil,nil}
	// Reject large encoded values before decoding.
	if len(raw)>8*headerMaxBytes{return nil,errors.New("header packet too large")}
	switch strings.ToLower(typ){
	case "","array":
		var b []byte
		err:=json.Unmarshal(raw,&b)
		return b,err
	case "str","hex","base64":
		var s string
		if err:=json.Unmarshal(raw,&s);err!=nil{return nil,err}
		switch strings.ToLower(typ){
		case "str":return []byte(s),nil
		case "hex":return hex.DecodeString(s)
		default:return base64.StdEncoding.DecodeString(s)
		}
	default:return nil,errors.New("unsupported header packet type")
	}
}

func NewTCPHeader(o *option.LXFinalMaskTCPHeaderOptions)(*TCPHeader,error){
	if o==nil{return nil,nil}
	if len(o.Errors)!=0{return nil,errors.New("finalmask_tcp_header: error sequences unsupported")}
	if len(o.Clients)+len(o.Servers)>headerMaxItems{return nil,errors.New("finalmask_tcp_header: too many rounds")}
	total,items,budget:=0,0,0
	compile:=func(seqs [][]option.LXFinalMaskTCPHeaderItem, sending bool)([][]headerItem,error){
		out:=make([][]headerItem,0,len(seqs))
		for _,seq:=range seqs{
			var round []headerItem
			for _,item:=range seq{
				items++
				if items>headerMaxItems{return nil,errors.New("too many header items")}
				if item.Capture!=""||item.Reuse!=""||len(item.Transform)!=0{return nil,errors.New("stateful header items unsupported")}
				if item.Rand<0||item.Rand>headerMaxBytes||(item.Rand>0&&len(item.Packet)!=0){return nil,errors.New("invalid random header item")}
				packet,err:=headerBytes(item.Packet,item.Type)
				if err!=nil{return nil,err}
				lo,hi,err:=headerRange(item.RandRange,0,255,255)
				if err!=nil{return nil,err}
				dlo,dhi,err:=headerRange(item.Delay,0,0,5000)
				if err!=nil{return nil,err}
				total+=len(packet)+item.Rand
				if total>headerMaxBytes{return nil,errors.New("header byte budget exceeded")}
				if sending{budget+=dhi}
				if budget>5000{return nil,errors.New("header delay budget exceeded")}
				round=append(round,headerItem{packet:packet,random:item.Rand,lo:lo,hi:hi,delayLo:dlo,delayHi:dhi})
			}
			out=append(out,round)
		}
		return out,nil
	}
	clients,err:=compile(o.Clients,true)
	if err!=nil{return nil,fmt.Errorf("finalmask_tcp_header clients: %w",err)}
	servers,err:=compile(o.Servers,false)
	if err!=nil{return nil,fmt.Errorf("finalmask_tcp_header servers: %w",err)}
	return &TCPHeader{clients:clients,servers:servers},nil
}

func headerWrite(w io.Writer,p []byte)error{
	if len(p)==0{return nil}
	n,err:=w.Write(p)
	if err!=nil{return err}
	if n!=len(p){return io.ErrShortWrite}
	return nil
}

func headerPause(ctx context.Context,item headerItem)error{
	ms:=item.delayLo
	if item.delayHi>ms{ms+=mathrand.Intn(item.delayHi-ms+1)}
	if ms==0{return ctx.Err()}
	t:=time.NewTimer(time.Duration(ms)*time.Millisecond)
	defer t.Stop()
	select{
	case <-ctx.Done():return ctx.Err()
	case <-t.C:return ctx.Err()
	}
}

func headerRandom(item headerItem)([]byte,error){
	b:=make([]byte,item.random)
	if item.lo==0&&item.hi==255{_,err:=rand.Read(b);return b,err}
	if item.lo==item.hi{for i:=range b{b[i]=byte(item.lo)};return b,nil}
	span:=big.NewInt(int64(item.hi-item.lo+1))
	for i:=range b{n,err:=rand.Int(rand.Reader,span);if err!=nil{return nil,err};b[i]=byte(int(n.Int64())+item.lo)}
	return b,nil
}

func sendHeader(ctx context.Context,c net.Conn,seq []headerItem)error{
	var merged []byte
	for _,item:=range seq{
		if err:=ctx.Err();err!=nil{return err}
		if item.delayHi>0{
			if err:=headerWrite(c,merged);err!=nil{return err}
			merged=nil
			if err:=headerPause(ctx,item);err!=nil{return err}
		}
		if item.random>0{
			b,err:=headerRandom(item)
			if err!=nil{return err}
			merged=append(merged,b...)
		}else{merged=append(merged,item.packet...)}
	}
	return headerWrite(c,merged)
}

func receiveHeader(c net.Conn,seq []headerItem)error{
	for _,item:=range seq{
		size:=len(item.packet)+item.random
		if size==0{continue}
		buf:=make([]byte,size)
		if _,err:=io.ReadFull(c,buf);err!=nil{return err}
		// Like Xray, random receive items are consumed without checking value.
		if item.random==0&&!bytes.Equal(buf,item.packet){return errors.New("header auth failed: static response mismatch")}
	}
	return nil
}

// Handshake performs the Xray client/server round ordering before returning
// the original stream. A matching server is mandatory. A context cancellation
// or timeout closes the stream; no cancellation watcher survives success.
// This eager exchange is intentionally different from Xray's first-write hook.
func(h *TCPHeader) Handshake(ctx context.Context,c net.Conn)(net.Conn,error){
	ctx,cancel:=context.WithTimeout(ctx,headerTimeout)
	defer cancel()
	stop:=context.AfterFunc(ctx,func(){_ = c.Close()})
	exchange:=func()error{
		j:=0
		for _,seq:=range h.clients{
			if err:=sendHeader(ctx,c,seq);err!=nil{return err}
			if j<len(h.servers){
				if err:=receiveHeader(c,h.servers[j]);err!=nil{return err}
				j++
			}
		}
		for ;j<len(h.servers);j++{if err:=receiveHeader(c,h.servers[j]);err!=nil{return err}}
		return nil
	}
	err:=exchange()
	stopped:=stop()
	if ctx.Err()!=nil{err=ctx.Err()}else if !stopped&&err==nil{err=context.Canceled}
	if err!=nil{_ = c.Close();return nil,fmt.Errorf("finalmask_tcp_header: %w",err)}
	return c,nil
}
