package finalmask

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/common/finalmask/sudoku"
	"github.com/sagernet/sing-box/common/finalmask/xmc"
)

type tcpMask struct {
	fragment *TCPFragment
	header *TCPHeader
	sudoku *sudoku.Mask
	xmc *xmc.Mask
}

// TCPChain is immutable. Its configured order follows Xray: the first
// entry is the outermost wrapper. The connection is assembled in reverse.
type TCPChain struct { masks []tcpMask }

func decodeMaskSettings(data json.RawMessage, dst any) error {
	if len(data)==0 || bytes.Equal(bytes.TrimSpace(data),[]byte("null")) {
		return errors.New("missing mask settings")
	}
	d:=json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err:=d.Decode(dst);err!=nil{return err}
	if err:=d.Decode(new(any));err!=io.EOF{return errors.New("invalid trailing mask settings")}
	return nil
}

// Fragment settings in Xray accept numbers and string ranges. Normalize
// them to the existing validated LX options; the legacy snake_case alias
// is accepted, but specifying both spellings is ambiguous.
type fragmentSettings struct {
	Packets string `json:"packets"`
	Length json.RawMessage `json:"length"`
	Lengths []json.RawMessage `json:"lengths"`
	Delay json.RawMessage `json:"delay"`
	Delays []json.RawMessage `json:"delays"`
	MaxSplit json.RawMessage `json:"maxSplit"`
	MaxSplitLX json.RawMessage `json:"max_split"`
}

func fragmentRangeString(raw json.RawMessage)(string,error){
	if len(raw)==0{return "",nil}
	if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")){return "",errors.New("null fragment range")}
	var s string
	if err:=json.Unmarshal(raw,&s);err==nil{return s,nil}
	var n int
	if err:=json.Unmarshal(raw,&n);err!=nil{return "",err}
	return strconv.Itoa(n),nil
}

func fragmentRangeList(raw []json.RawMessage)([]string,error){
	if len(raw)>256{return nil,errors.New("too many fragment ranges")}
	out:=make([]string,0,len(raw))
	for _,r:=range raw {
		s,err:=fragmentRangeString(r)
		if err!=nil{return nil,err}
		out=append(out,s)
	}
	return out,nil
}

func compileFragmentSettings(raw json.RawMessage)(*TCPFragment,error){
	var s fragmentSettings
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if len(s.MaxSplit)!=0&&len(s.MaxSplitLX)!=0{return nil,errors.New("duplicate maxSplit/max_split")}
	if len(s.MaxSplit)==0{s.MaxSplit=s.MaxSplitLX}
	length,err:=fragmentRangeString(s.Length)
	if err!=nil{return nil,err}
	lengths,err:=fragmentRangeList(s.Lengths)
	if err!=nil{return nil,err}
	delay,err:=fragmentRangeString(s.Delay)
	if err!=nil{return nil,err}
	delays,err:=fragmentRangeList(s.Delays)
	if err!=nil{return nil,err}
	maxSplit,err:=fragmentRangeString(s.MaxSplit)
	if err!=nil{return nil,err}
	return NewTCPFragment(&option.LXFinalMaskFragmentOptions{
		Packets:s.Packets,Length:length,Lengths:lengths,Delay:delay,Delays:delays,MaxSplit:maxSplit,
	})
}

func NewTCPChain(opts []option.LXFinalMaskTCPMaskOptions)(*TCPChain,error){
	if len(opts)==0{return nil,nil}
	if len(opts)>4{return nil,errors.New("finalmask_tcp: at most four masks in pilot")}
	c:=&TCPChain{}
	seen:=make(map[string]bool)
	for i,o:=range opts{
		if seen[o.Type]{return nil,fmt.Errorf("finalmask_tcp[%d]: duplicate mask %q",i,o.Type)}
		seen[o.Type]=true
		var m tcpMask
		var err error
		switch o.Type{
		case "fragment":
			m.fragment,err=compileFragmentSettings(o.Settings)
		case "sudoku":
			var settings sudoku.Config
			if err=decodeMaskSettings(o.Settings,&settings);err==nil{m.sudoku,err=sudoku.New(&settings)}
		case "xmc":
			var settings xmc.Config
			if err=decodeMaskSettings(o.Settings,&settings);err==nil{m.xmc,err=xmc.New(&settings)}
		case "header-custom":
			var settings option.LXFinalMaskTCPHeaderOptions
			if err=decodeMaskSettings(o.Settings,&settings);err==nil{
				m.header,err=NewTCPHeader(&settings)
			}
		default:
			err=fmt.Errorf("unsupported mask %q",o.Type)
		}
		if err!=nil{return nil,fmt.Errorf("finalmask_tcp[%d]: %w",i,err)}
		c.masks=append(c.masks,m)
	}
	return c,nil
}

func (c *TCPChain) Wrap(ctx context.Context,conn net.Conn)(net.Conn,error){
	for i:=len(c.masks)-1;i>=0;i--{
		if err:=ctx.Err();err!=nil{_ = conn.Close();return nil,err}
		m:=c.masks[i]
		if m.fragment!=nil{
			conn=m.fragment.Wrap(conn)
		}else if m.xmc!=nil{
			wrapped,err:=m.xmc.WrapClient(conn)
			if err!=nil{_ = conn.Close();return nil,err}
			conn=wrapped
		}else if m.sudoku!=nil{
			conn=m.sudoku.WrapClient(conn)
		}else{
			// Handshake owns failure cleanup, including any inner fragment.
			wrapped,err:=m.header.Handshake(ctx,conn)
			if err!=nil{return nil,err}
			conn=wrapped
		}
	}
	if err:=ctx.Err();err!=nil{_ = conn.Close();return nil,err}
	return conn,nil
}
