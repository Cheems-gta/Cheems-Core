package quictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const testVMessUUID = "d342d11e-d424-4583-b36b-524ab1f0afa4"

type vmessTestNetwork struct{ protected atomic.Int32 }

func (n *vmessTestNetwork) Protect(int64) bool {
	n.protected.Add(1)
	return true
}

func (*vmessTestNetwork) Resolve(host string) (string, error) {
	return "", net.InvalidAddrError("unexpected resolve: " + host)
}

type vmessEchoHandler struct{}

func (vmessEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (vmessEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	if onClose != nil {
		onClose(nil)
	}
}

func startVMessEcho(t *testing.T, listener net.Listener, alterID int) *vmess.Service[string] {
	t.Helper()
	service := vmess.NewService[string](vmessEchoHandler{})
	if err := service.UpdateUsers([]string{"test-user"}, []string{testVMessUUID}, []int{alterID}); err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_ = service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil)
	}()
	return service
}

func TestVMessTCPDialSendsHandshakeThroughProtectedSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type accepted struct {
		header []byte
		err    error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			acceptedCh <- accepted{err: acceptErr}
			return
		}
		defer conn.Close()
		header := make([]byte, 16)
		_, readErr := io.ReadFull(conn, header)
		acceptedCh <- accepted{header: header, err: readErr}
	}()

	network := &vmessTestNetwork{}
	client, err := NewVMessClient(VMessConfig{
		Address: listener.Addr().String(), UserID: testVMessUUID,
		Security: "aes-128-gcm", Network: network, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenTCP(context.Background(), "example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	select {
	case got := <-acceptedCh:
		if got.err != nil {
			t.Fatal(got.err)
		}
		if len(got.header) != 16 {
			t.Fatalf("VMess auth header length = %d", len(got.header))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("VMess peer did not receive a request")
	}
	if network.protected.Load() != 1 {
		t.Fatalf("expected one protected upstream socket, got %d", network.protected.Load())
	}
}

func TestVMessRejectsUnsupportedSecurityAndAlterID(t *testing.T) {
	for _, cfg := range []VMessConfig{
		{Address: "127.0.0.1:443", UserID: testVMessUUID, Security: "aes-256-gcm", Network: &vmessTestNetwork{}},
		{Address: "127.0.0.1:443", UserID: testVMessUUID, Security: "auto", AlterID: 65536, Network: &vmessTestNetwork{}},
	} {
		if _, err := NewVMessClient(cfg); err == nil {
			t.Fatalf("accepted unsupported VMess config: %+v", cfg)
		}
	}
}

func TestVMessTLSRequiresValidCustomCAWhenProvided(t *testing.T) {
	_, err := NewVMessClient(VMessConfig{
		Address: "127.0.0.1:443", ServerName: "vmess.example", UserID: testVMessUUID,
		Security: "auto", TLS: true, TrustedCAPEM: "not a certificate", Network: &vmessTestNetwork{},
	})
	if err == nil {
		t.Fatal("accepted malformed VMess trusted CA")
	}
}

func TestVMessAEADRoundTripAgainstReferenceService(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	startVMessEcho(t, listener, 0)
	client, err := NewVMessClient(VMessConfig{
		Address: listener.Addr().String(), UserID: testVMessUUID,
		Security: "aes-128-gcm", Network: &vmessTestNetwork{}, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenTCP(context.Background(), "example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("vmess-aead-roundtrip")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("vmess-aead-roundtrip"))
	if _, err = io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "vmess-aead-roundtrip" {
		t.Fatalf("round-trip payload = %q", got)
	}
}

func TestVMessTLSRoundTripWithTrustedCertificate(t *testing.T) {
	seed := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	cert := seed.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		seed.Close()
		t.Fatal(err)
	}
	seed.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}})
	defer tlsListener.Close()
	startVMessEcho(t, tlsListener, 0)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	client, err := NewVMessClient(VMessConfig{
		Address: tlsListener.Addr().String(), ServerName: leaf.DNSNames[0], UserID: testVMessUUID,
		Security: "chacha20-poly1305", TLS: true, TrustedCAPEM: string(ca),
		Network: &vmessTestNetwork{}, Timeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenTCP(context.Background(), "example.org", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("vmess-tls-roundtrip")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("vmess-tls-roundtrip"))
	if _, err = io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "vmess-tls-roundtrip" {
		t.Fatalf("TLS round-trip payload = %q", got)
	}
}
