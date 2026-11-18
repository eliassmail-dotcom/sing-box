package tls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

type lxVerificationStub struct {
	rawCalls      atomic.Int32
	verifiedCalls atomic.Int32
	cert          stdtls.Certificate
}

func (d *lxVerificationStub) DialContext(ctx context.Context, network string, target M.Socksaddr) (net.Conn, error) {
	d.rawCalls.Add(1)
	return nil, context.Canceled // Direct TCP path must not be used in the experiment.
}

func (d *lxVerificationStub) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, context.Canceled
}

func (d *lxVerificationStub) IPRaceEnabled() bool { return true }

func (d *lxVerificationStub) DialVerifiedTCP(ctx context.Context, target M.Socksaddr, verify func(context.Context, net.Conn) (net.Conn, error)) (net.Conn, error) {
	d.verifiedCalls.Add(1)
	// A responsive TCP listener that does not speak the expected TLS protocol
	// must NOT win, even though net.Pipe has already established a socket.
	tcpButNoTLS, decoy := net.Pipe()
	_ = decoy.Close()
	conn, err := verify(ctx, tcpButNoTLS)
	_ = tcpButNoTLS.Close()
	if conn != nil {
		_ = conn.Close()
		panic("unverified TCP endpoint was accepted")
	}
	if err == nil {
		panic("decoy TLS handshake unexpectedly passed")
	}

	// Second endpoint completes an authentic TLS handshake using the SAME
	// logical SNI as the domain, not an IP-literal server name.
	client, server := net.Pipe()
	tlsServer := stdtls.Server(server, &stdtls.Config{Certificates: []stdtls.Certificate{d.cert}})
	go func() {
		_ = tlsServer.HandshakeContext(ctx)
		// Keep the connection alive for the caller, which owns client.
		<-ctx.Done()
		_ = tlsServer.Close()
	}()
	verified, err := verify(ctx, client)
	if err != nil {
		_ = client.Close()
		_ = tlsServer.Close()
		return nil, err
	}
	return verified, nil
}

func TestLXVerifiedDialerUsesAuthenticatedTLSNotFirstTCP(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"uk.example.test"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool.AddCert(parsed)

	stub := &lxVerificationStub{cert: stdtls.Certificate{
		Certificate: [][]byte{der}, PrivateKey: priv,
	}}
	dialer := NewDialer(stub, &STDClientConfig{
		config:           &stdtls.Config{RootCAs: pool, ServerName: "uk.example.test"},
		serverName:       "uk.example.test",
		handshakeTimeout: 2 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialTLSContext(ctx, M.Socksaddr{Fqdn: "uk.example.test", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.ServerName != "uk.example.test" {
		t.Fatalf("TLS handshake or SNI incorrect: complete=%v SNI=%q", state.HandshakeComplete, state.ServerName)
	}
	if stub.verifiedCalls.Load() != 1 || stub.rawCalls.Load() != 0 {
		t.Fatalf("dialer bypassed verified racing: verified=%d raw=%d", stub.verifiedCalls.Load(), stub.rawCalls.Load())
	}
}
