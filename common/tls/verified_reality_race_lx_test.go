//go:build with_utls && with_lx_command

package tls

import (
    "context"
    "crypto/ecdh"
    "crypto/rand"
    stdtls "crypto/tls"
    "encoding/base64"
    "errors"
    "io"
    "net"
    "sync/atomic"
    "testing"
    "time"

    "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing/common/json/badoption"
    "github.com/sagernet/sing/common/logger"
    M "github.com/sagernet/sing/common/metadata"
)

// A working TCP endpoint serving the decoy's ordinary TLS certificate must
// NOT be mistaken for an authenticated REALITY server. The downstream
// ResolveDialer uses this same callback; the test verifies its real consumer,
// common/tls, with an actual REALITY server instead of a mocked certificate.
type lxRealityVerifiedEndpointStub struct {
    decoyAddr string
    realityAddr string
    verificationAttempts atomic.Int32
    rawCalls atomic.Int32
}

func (s *lxRealityVerifiedEndpointStub) DialContext(context.Context,string,M.Socksaddr)(net.Conn,error) {
    s.rawCalls.Add(1)
    return nil,errors.New("unexpected raw TCP dial")
}
func (s *lxRealityVerifiedEndpointStub) ListenPacket(context.Context,M.Socksaddr)(net.PacketConn,error) {
    return nil,errors.New("unsupported")
}
func (s *lxRealityVerifiedEndpointStub) IPRaceEnabled() bool { return true }
func (s *lxRealityVerifiedEndpointStub) DialVerifiedTCP(
    ctx context.Context, _ M.Socksaddr,
    verify func(context.Context,net.Conn)(net.Conn,error),
)(net.Conn,error) {
    var last error
    for _, endpoint := range []string{s.decoyAddr,s.realityAddr} {
        raw,err:= (&net.Dialer{}).DialContext(ctx,"tcp",endpoint)
        if err!=nil{return nil,err}
        s.verificationAttempts.Add(1)
        verified,err:=verify(ctx,raw)
        if err==nil {
            if endpoint == s.decoyAddr {
                _=verified.Close()
                return nil,errors.New("REALITY decoy incorrectly accepted as authenticated")
            }
            return verified,nil
        }
        _=raw.Close()
        last=err
    }
    return nil,last
}

func TestLXIPRaceRequiresActualREALITYAuthentication(t *testing.T) {
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()

    target,err:=stdtls.Listen("tcp","127.0.0.1:0",&stdtls.Config{
        Certificates:[]stdtls.Certificate{lxReleaseCert(t,"www.example.com")},
    })
    if err!=nil{t.Fatal(err)}
    defer target.Close()
    go func(){
        for {
            conn,err:=target.Accept()
            if err!=nil{return}
            go func(){defer conn.Close();_,_=io.Copy(io.Discard,conn)}()
        }
    }()

    // Decoy: TCP and TLS both respond; the REALITY signature is absent.
    decoy,err:=stdtls.Listen("tcp","127.0.0.1:0",&stdtls.Config{
        Certificates:[]stdtls.Certificate{lxReleaseCert(t,"www.example.com")},
    })
    if err!=nil{t.Fatal(err)}
    defer decoy.Close()
    go func(){
        for {
            conn,err:=decoy.Accept()
            if err!=nil{return}
            go func(){defer conn.Close();_,_=io.Copy(io.Discard,conn)}()
        }
    }()

    privateKey,err:=ecdh.X25519().GenerateKey(rand.Reader)
    if err!=nil{t.Fatal(err)}
    serverConfig,err:=NewRealityServer(context.Background(),logger.NOP(),option.InboundTLSOptions{
        Enabled:true,
        ServerName:"www.example.com",
        Reality:&option.InboundRealityOptions{
            Enabled:true,
            Handshake:option.InboundRealityHandshakeOptions{
                ServerOptions:option.ServerOptions{
                    Server:"127.0.0.1", ServerPort:uint16(target.Addr().(*net.TCPAddr).Port),
                },
            },
            PrivateKey:base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
            ShortID:badoption.Listable[string]{"0123abcd"},
        },
    })
    if err!=nil{t.Fatal(err)}
    listener,err:=net.Listen("tcp","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer listener.Close()
    go func(){
        for {
            raw,err:=listener.Accept()
            if err!=nil{return}
            go func(){
                verified,err:=ServerHandshake(context.Background(),raw,serverConfig)
                if err!=nil{_ = raw.Close();return}
                defer verified.Close()
                _,_ = io.Copy(verified,verified)
            }()
        }
    }()

    clientConfig,err:=NewRealityClient(context.Background(),logger.NOP(),"www.example.com",option.OutboundTLSOptions{
        Enabled:true,ServerName:"www.example.com",
        UTLS:&option.OutboundUTLSOptions{Enabled:true,Fingerprint:"chrome"},
        Reality:&option.OutboundRealityOptions{
            Enabled:true,
            PublicKey:base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()),
            ShortID:"0123abcd",
        },
    })
    if err!=nil{t.Fatal(err)}

    stub:=&lxRealityVerifiedEndpointStub{
        decoyAddr:decoy.Addr().String(), realityAddr:listener.Addr().String(),
    }
    dialer:=NewDialer(stub,clientConfig)
    conn,err:=dialer.DialTLSContext(ctx,M.Socksaddr{Fqdn:"www.example.com",Port:443})
    if err!=nil{t.Fatal(err)}
    defer conn.Close()
    if !conn.ConnectionState().HandshakeComplete ||
        stub.verificationAttempts.Load()!=2 ||
        stub.rawCalls.Load()!=0 {
        t.Fatalf("REALITY race did not reject first decoy: verified=%v attempts=%d raw=%d",
            conn.ConnectionState().HandshakeComplete,
            stub.verificationAttempts.Load(), stub.rawCalls.Load())
    }
}
