package quictransport

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type anyTLSEchoHandler struct{}

func (anyTLSEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
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

type anyTLSAllowNetwork struct{}

func (anyTLSAllowNetwork) Protect(int64) bool { return true }
func (anyTLSAllowNetwork) Resolve(host string) (string, error) {
	if host == "anytls.test" {
		return "127.0.0.1", nil
	}
	return "", net.InvalidAddrError("unexpected test hostname")
}

func TestAnyTLSClientTLSAuthAndMultiplexedTCP(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()

	plainListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(plainListener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	server, err := anytls.NewService(anytls.ServiceConfig{
		Users:         []anytls.User{{Name: "test", Password: "correct horse"}},
		PaddingScheme: padding.DefaultPaddingScheme,
		Handler:       anyTLSEchoHandler{},
		Logger:        logger.NOP(),
	})
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				tlsConn := conn.(*tls.Conn)
				if tlsConn.Handshake() != nil {
					_ = conn.Close()
					return
				}
				_ = server.NewConnection(serverCtx, tlsConn, M.Socksaddr{}, nil)
			}(conn)
		}
	}()

	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	client, err := NewAnyTLSClient(context.Background(), AnyTLSConfig{
		Address:    net.JoinHostPort("anytls.test", strconv.Itoa(int(listener.Addr().(*net.TCPAddr).AddrPort().Port()))),
		ServerName: "example.com", Password: "correct horse", Network: anyTLSAllowNetwork{},
		TrustedCAPEM: string(certificatePEM), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	stream, err := client.OpenTCP(context.Background(), "echo.test", 8080)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if deadline, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadline.SetDeadline(time.Now().Add(5 * time.Second))
	}
	want := []byte("AnyTLS stream round trip")
	if _, err = stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err = io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("round trip = %q, want %q", got, want)
	}
}
