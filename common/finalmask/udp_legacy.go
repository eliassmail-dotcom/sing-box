package finalmask

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"hash/fnv"
	"io"
	"net"
	"strings"
	"sync"
)

// Wire layouts follow Xray v26.11.9 finalmask/mkcp. These are packet
// masks, not an implementation of the mKCP transport itself.
type udpLegacyConfig struct {
	kind string
	prefix []byte
	size int
	aead cipher.AEAD
}

func compileUDPLegacy(raw json.RawMessage)(*udpLegacyConfig,error){
	var s struct{
		Header string `json:"header"`
		Value string `json:"value"`
	}
	if err:=decodeMaskSettings(raw,&s);err!=nil{return nil,err}
	if len(s.Value)>1024{return nil,errors.New("mkcp-legacy value too long")}
	c:=&udpLegacyConfig{kind:strings.ToLower(s.Header)}
	switch c.kind{
	case "":
		if s.Value==""{c.kind="original";c.size=6;break}
		key:=sha256.Sum256([]byte(s.Value))
		block,err:=aes.NewCipher(key[:16]);if err!=nil{return nil,err}
		c.aead,err=cipher.NewGCM(block);if err!=nil{return nil,err}
		c.kind="aes128gcm"
		c.size=c.aead.NonceSize()+c.aead.Overhead()
	case "dns":
		domain:=s.Value
		if domain==""{domain="www.baidu.com"}
		// Ordinary DNS labels only; escaped and empty labels rejected.
		if len(domain)>253{return nil,errors.New("mkcp-legacy DNS name too long")}
		p:=[]byte{0,0,1,0,0,1,0,0,0,0,0,0}
		for _,label:=range strings.Split(domain,"."){
			if len(label)==0||len(label)>63||strings.ContainsAny(label,"\\\x00"){return nil,errors.New("invalid mkcp-legacy DNS label")}
			p=append(p,byte(len(label)));p=append(p,label...)
		}
		c.prefix=append(p,0,0,1,0,1)
		c.size=len(c.prefix)
	case "dtls","wechat":c.size=13
	case "srtp","utp","wireguard":c.size=4
	default:return nil,errors.New("unknown mkcp-legacy header")
	}
	return c,nil
}

type udpLegacyConn struct{
	net.Conn
	config *udpLegacyConfig
	readMu,writeMu sync.Mutex
	sequence uint32
	dtlsLength uint16
	rbuf [udpWireLimit+1]byte
	wbuf [udpWireLimit]byte
}

func(c *udpLegacyConn)encode(p []byte)([]byte,error){
	wire:=c.wbuf[:c.config.size+len(p)]
	h:=wire[:c.config.size]
	clear(h)
	switch c.config.kind{
	case "original":
		binary.BigEndian.PutUint16(h[4:],uint16(len(p)))
		copy(wire[6:],p)
		hash:=fnv.New32a()
		_,_=hash.Write(wire[4:])
		binary.BigEndian.PutUint32(h,hash.Sum32())
		for i:=4;i<len(wire);i++{wire[i]^=wire[i-4]}
		return wire,nil
	case "aes128gcm":
		a:=c.config.aead
		nonce:=wire[:a.NonceSize()]
		if _,err:=rand.Read(nonce);err!=nil{return nil,err}
		return a.Seal(nonce,nonce,p,nil),nil
	case "dns":
		copy(h,c.config.prefix)
		if _,err:=rand.Read(h[:2]);err!=nil{return nil,err}
	case "dtls":
		h[0],h[1],h[2]=23,254,253
		binary.BigEndian.PutUint32(h[7:],c.sequence)
		c.sequence++
		binary.BigEndian.PutUint16(h[11:],c.dtlsLength)
		c.dtlsLength+=17
		if c.dtlsLength>100{c.dtlsLength-=50}
	case "srtp":
		c.sequence++
		binary.BigEndian.PutUint16(h[2:],uint16(c.sequence))
	case "utp":
		// Upstream initializes all four fields to zero.
	case "wechat":
		c.sequence++
		h[0],h[1]=0xa1,0x08
		binary.BigEndian.PutUint32(h[2:],c.sequence)
		copy(h[6:],[]byte{0,0x10,0x11,0x18,0x30,0x22,0x30})
	case "wireguard":h[0]=4
	}
	copy(wire[c.config.size:],p)
	return wire,nil
}

func(c *udpLegacyConn)Write(p []byte)(int,error){
	if len(p)>udpWireLimit-c.config.size{return 0,errors.New("mkcp-legacy datagram too large")}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	wire,err:=c.encode(p)
	if err!=nil{return 0,err}
	n,err:=c.Conn.Write(wire)
	if err!=nil{return 0,err}
	if n!=len(wire){return 0,io.ErrShortWrite}
	return len(p),nil
}

func(c *udpLegacyConn)decode(wire []byte)([]byte,bool){
	if len(wire)<c.config.size{return nil,false}
	switch c.config.kind{
	case "original":
		for i:=len(wire)-1;i>=4;i--{wire[i]^=wire[i-4]}
		hash:=fnv.New32a()
		_,_=hash.Write(wire[4:])
		if binary.BigEndian.Uint32(wire)!=hash.Sum32()||int(binary.BigEndian.Uint16(wire[4:]))!=len(wire)-6{return nil,false}
		return wire[6:],true
	case "aes128gcm":
		a:=c.config.aead
		ns:=a.NonceSize()
		b,err:=a.Open(wire[ns:ns],wire[:ns],wire[ns:],nil)
		return b,err==nil
	default:
		// Upstream header variants strip a fixed prefix; they do not
		// authenticate or validate the prefix fields.
		return wire[c.config.size:],true
	}
}

func(c *udpLegacyConn)Read(p []byte)(int,error){
	if len(p)==0{return 0,nil}
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for{
		n,err:=c.Conn.Read(c.rbuf[:])
		if err!=nil{return 0,err}
		if n>udpWireLimit{continue}
		b,ok:=c.decode(c.rbuf[:n])
		if !ok||len(b)>len(p){continue}
		return copy(p,b),nil
	}
}
