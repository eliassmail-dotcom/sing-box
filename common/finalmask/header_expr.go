package finalmask

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
)

// A typed, bounded expression tree for Xray's header-custom vocabulary.
// width is the statically known byte width, or -1 for uint64.
type headerExpr struct {
	kind, name string
	b []byte
	n uint64
	width int
	args []*headerExpr
}
type headerExprValue struct { b []byte; n uint64 }
type headerExprCompiler struct {
	sizes map[string]int
	nodes, work int
}
type headerTransformJSON struct {
	Op string `json:"op"`
	Args []json.RawMessage `json:"args"`
}
type headerTransformArgJSON struct {
	Type string `json:"type"`
	Bytes json.RawMessage `json:"bytes"`
	U64 *uint64 `json:"u64"`
	Reuse string `json:"reuse"`
	Metadata string `json:"metadata"`
	Transform json.RawMessage `json:"transform"`
}

func(c *headerExprCompiler) account(e *headerExpr,depth int) error {
	c.nodes++
	if c.nodes>256||depth>12{return errors.New("header transform complexity exceeded")}
	if e.width>headerMaxBytes{return errors.New("header transform byte limit exceeded")}
	if e.width>=0{c.work+=e.width}
	if c.work>256*1024{return errors.New("header transform work budget exceeded")}
	return nil
}
func(c *headerExprCompiler) arg(raw json.RawMessage,depth int)(*headerExpr,error){
	if depth>12{return nil,errors.New("header transform depth exceeded")}
	var a headerTransformArgJSON
	if err:=decodeMaskSettings(raw,&a);err!=nil{return nil,err}
	count:=0
	for _,v:=range []bool{len(a.Bytes)!=0,a.U64!=nil,a.Reuse!="",a.Metadata!="",len(a.Transform)!=0}{if v{count++}}
	if count!=1{return nil,errors.New("header transform arg must have exactly one value")}
	e:=&headerExpr{}
	switch {
	case len(a.Bytes)!=0:
		b,err:=headerBytes(a.Bytes,a.Type);if err!=nil{return nil,err}
		e.kind="bytes";e.b=b;e.width=len(b)
	case a.U64!=nil:
		e.kind="u64";e.n=*a.U64;e.width=-1
	case a.Reuse!="":
		w,ok:=c.sizes[a.Reuse];if !ok{return nil,fmt.Errorf("unknown header variable %q",a.Reuse)}
		e.kind="reuse";e.name=a.Reuse;e.width=w
	case a.Metadata!="":
		switch a.Metadata{
		case "local_port","remote_port","src_port_u16","dst_port_u16","local_ip4_u32","remote_ip4_u32","src_ip4_u32","dst_ip4_u32":
		default:return nil,fmt.Errorf("unknown header metadata %q",a.Metadata)
		}
		e.kind="metadata";e.name=a.Metadata;e.width=-1
	default:return c.compile(a.Transform,depth)
	}
	if err:=c.account(e,depth);err!=nil{return nil,err}
	return e,nil
}
func(c *headerExprCompiler) compile(raw json.RawMessage,depth int)(*headerExpr,error){
	if depth>12||len(raw)>256*1024{return nil,errors.New("header transform input limit exceeded")}
	var x headerTransformJSON
	if err:=decodeMaskSettings(raw,&x);err!=nil{return nil,err}
	if len(x.Args)==0||len(x.Args)>64{return nil,errors.New("invalid header transform arg count")}
	e:=&headerExpr{kind:x.Op,width:-1}
	for _,rawArg:=range x.Args{
		a,err:=c.arg(rawArg,depth+1);if err!=nil{return nil,err}
		e.args=append(e.args,a)
	}
	a:=e.args
	isB:=func(i int)bool{return i<len(a)&&a[i].width>=0}
	isN:=func(i int)bool{return i<len(a)&&a[i].width<0}
	literalLength:=func(i int)(int,error){
		if i>=len(a)||a[i].kind!="u64"||a[i].n>headerMaxBytes{return 0,errors.New("header transform length must be bounded literal u64")}
		return int(a[i].n),nil
	}
	bad:=func()(*headerExpr,error){return nil,fmt.Errorf("invalid arguments for header transform %q",x.Op)}
	switch x.Op{
	case "concat":
		e.width=0
		for _,arg:=range a{if arg.width<0{return bad()};e.width+=arg.width;if e.width>headerMaxBytes{return bad()}}
	case "slice":
		if len(a)!=3||!isB(0)||!isN(1){return bad()}
		w,err:=literalLength(2);if err!=nil{return nil,err}
		if w>a[0].width{return bad()}
		if a[1].kind=="u64"&&a[1].n>uint64(a[0].width-w){return bad()}
		e.width=w
	case "pad":
		if len(a)!=3||!isB(0)||!isB(2)||a[2].width==0{return bad()}
		w,err:=literalLength(1);if err!=nil{return nil,err}
		if w<a[0].width{return bad()};e.width=w
	case "truncate":
		if len(a)!=2||!isB(0){return bad()}
		w,err:=literalLength(1);if err!=nil{return nil,err}
		if w>a[0].width{return bad()};e.width=w
	case "be16","le16","be32","le32","le64":
		if len(a)!=1||!isN(0){return bad()}
		switch x.Op{case "be16","le16":e.width=2;case "be32","le32":e.width=4;default:e.width=8}
	case "xor16","xor32","add","sub","and","or","shl","shr":
		if len(a)!=2||!isN(0)||!isN(1){return bad()}
	default:return nil,fmt.Errorf("unsupported header transform %q",x.Op)
	}
	if err:=c.account(e,depth);err!=nil{return nil,err}
	return e,nil
}

func(e *headerExpr) eval(vars map[string][]byte,metadata map[string]uint64)(headerExprValue,error){
	var out headerExprValue
	switch e.kind{
	case "bytes":out.b=e.b;return out,nil
	case "u64":out.n=e.n;return out,nil
	case "reuse":
		b,ok:=vars[e.name];if !ok||len(b)!=e.width{return out,fmt.Errorf("missing or invalid header variable %q",e.name)}
		out.b=b;return out,nil
	case "metadata":
		n,ok:=metadata[e.name];if !ok{return out,fmt.Errorf("missing header metadata %q",e.name)}
		out.n=n;return out,nil
	}
	a:=make([]headerExprValue,len(e.args))
	for i,child:=range e.args{v,err:=child.eval(vars,metadata);if err!=nil{return out,err};a[i]=v}
	bad:=func()(headerExprValue,error){return headerExprValue{},fmt.Errorf("header transform %s overflow or bounds",e.kind)}
	switch e.kind{
	case "concat":
		out.b=make([]byte,0,e.width)
		for _,v:=range a{out.b=append(out.b,v.b...)}
	case "slice":
		if a[1].n>uint64(len(a[0].b)-e.width){return bad()}
		start:=int(a[1].n);out.b=a[0].b[start:start+e.width]
	case "truncate":out.b=a[0].b[:e.width]
	case "pad":
		out.b=make([]byte,e.width);copy(out.b,a[0].b)
		for i:=len(a[0].b);i<len(out.b);i++{out.b[i]=a[2].b[(i-len(a[0].b))%len(a[2].b)]}
	case "be16","le16","be32","le32","le64":
		out.b=make([]byte,e.width)
		var order binary.ByteOrder=binary.LittleEndian
		if e.kind=="be16"||e.kind=="be32"{order=binary.BigEndian}
		switch e.width{
		case 2:if a[0].n>math.MaxUint16{return bad()};order.PutUint16(out.b,uint16(a[0].n))
		case 4:if a[0].n>math.MaxUint32{return bad()};order.PutUint32(out.b,uint32(a[0].n))
		case 8:order.PutUint64(out.b,a[0].n)
		}
	case "xor16","xor32":
		max:=uint64(math.MaxUint32);if e.kind=="xor16"{max=math.MaxUint16}
		if a[0].n>max||a[1].n>max{return bad()};out.n=a[0].n^a[1].n
	case "add":if a[0].n>math.MaxUint64-a[1].n{return bad()};out.n=a[0].n+a[1].n
	case "sub":if a[0].n<a[1].n{return bad()};out.n=a[0].n-a[1].n
	case "and":out.n=a[0].n&a[1].n
	case "or":out.n=a[0].n|a[1].n
	case "shl":if a[1].n>=64||a[0].n>math.MaxUint64>>a[1].n{return bad()};out.n=a[0].n<<a[1].n
	case "shr":if a[1].n>=64{return bad()};out.n=a[0].n>>a[1].n
	default:return out,errors.New("invalid compiled header transform")
	}
	if e.width>=0&&len(out.b)!=e.width{return bad()}
	return out,nil
}

func headerMetadata(c net.Conn)map[string]uint64{
	m:=make(map[string]uint64)
	load:=func(prefix,alias string,addr net.Addr){
		var ip net.IP;var port int
		switch v:=addr.(type){case *net.TCPAddr:ip=v.IP;port=v.Port;case *net.UDPAddr:ip=v.IP;port=v.Port;default:return}
		m[prefix+"_port"]=uint64(port);m[alias+"_port_u16"]=uint64(port)
		if b:=ip.To4();b!=nil{v:=uint64(binary.BigEndian.Uint32(b));m[prefix+"_ip4_u32"]=v;m[alias+"_ip4_u32"]=v}
	}
	load("local","dst",c.LocalAddr())
	load("remote","src",c.RemoteAddr())
	return m
}
