package quictransport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
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

// Runs the upstream AnyTLS service over a real TCP/TLS socket.
func anyTLSTestServer(t *testing.T) (string, string, string) {
	t.Helper()
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(plain, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"anytls-test", "h2", "http/1.1"}})
	server, err := anytls.NewService(anytls.ServiceConfig{Users: []anytls.User{{Name: "test", Password: "correct horse"}}, PaddingScheme: padding.DefaultPaddingScheme, Handler: anyTLSEchoHandler{}, Logger: logger.NOP()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tc := conn.(*tls.Conn)
				tc.SetDeadline(time.Now().Add(10 * time.Second))
				if tc.Handshake() != nil {
					return
				}
				_ = server.NewConnection(ctx, tc, M.Socksaddr{}, nil)
			}(conn)
		}
	}()
	address := net.JoinHostPort("anytls.test", strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}))
	pin := fmt.Sprintf("%x", sha256.Sum256(cert.Certificate[0]))
	return address, ca, pin
}

func anyTLSRoundTrip(client *AnyTLSClient, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := client.OpenTCP(ctx, "echo.test", 8080)
	if err != nil {
		return err
	}
	defer conn.Close()
	if d, ok := conn.(interface{ SetDeadline(time.Time) error }); ok {
		d.SetDeadline(time.Now().Add(3 * time.Second))
	}
	if _, err = conn.Write([]byte(message)); err != nil {
		return err
	}
	got := make([]byte, len(message))
	if _, err = io.ReadFull(conn, got); err != nil {
		return err
	}
	if string(got) != message {
		return fmt.Errorf("unexpected forwarded data %q", got)
	}
	return nil
}

func TestAnyTLSFingerprintsForwardWithSelfSignedMismatchedCertificate(t *testing.T) {
	address, _, _ := anyTLSTestServer(t)
	for _, fingerprint := range []string{"", "none", "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"} {
		for _, customALPN := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/custom-alpn=%v", fingerprint, customALPN), func(t *testing.T) {
				cfg := AnyTLSConfig{Address: address, ServerName: "wrong-name.example", Password: "correct horse", Network: anyTLSAllowNetwork{}, Fingerprint: fingerprint, AllowUnverifiedTLS: true}
				if customALPN {
					cfg.ALPN = []string{"anytls-test"}
				}
				client, err := NewAnyTLSClient(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				// Parallel streams exercise the actual AnyTLS multiplexing implementation.
				var wg sync.WaitGroup
				failures := make(chan error, 8)
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						failures <- anyTLSRoundTrip(client, fmt.Sprintf("stream-%d-%s", i, fingerprint))
					}(i)
				}
				wg.Wait()
				close(failures)
				for err := range failures {
					if err != nil {
						t.Error(err)
					}
				}
				if err := anyTLSRoundTrip(client, "session reuse"); err != nil {
					t.Error(err)
				}
			})
		}
	}
}

func TestAnyTLSStrictTLSAndPinArePreservedForNativeCallers(t *testing.T) {
	address, ca, pin := anyTLSTestServer(t)
	for _, fp := range []string{"", "chrome", "firefox"} {
		for _, scenario := range []string{"trusted", "unknown-ca", "wrong-hostname", "correct-pin", "wrong-pin", "wrong-password"} {
			t.Run(fp+"/"+scenario, func(t *testing.T) {
				cfg := AnyTLSConfig{Address: address, ServerName: "example.com", Password: "correct horse", Network: anyTLSAllowNetwork{}, Fingerprint: fp, TrustedCAPEM: ca}
				switch scenario {
				case "unknown-ca":
					cfg.TrustedCAPEM = ""
				case "wrong-hostname":
					cfg.ServerName = "wrong.example"
				case "correct-pin":
					cfg.CertificateSHA256 = pin
				case "wrong-pin":
					cfg.AllowUnverifiedTLS = true
					cfg.CertificateSHA256 = fmt.Sprintf("%064x", 1)
				case "wrong-password":
					cfg.AllowUnverifiedTLS = true
					cfg.Password = "incorrect"
				}
				client, err := NewAnyTLSClient(context.Background(), cfg)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				err = anyTLSRoundTrip(client, "authenticated payload")
				success := scenario == "trusted" || scenario == "correct-pin"
				if (err == nil) != success {
					t.Fatalf("success=%v, error=%v", success, err)
				}
			})
		}
	}
}

func TestAnyTLSRejectsUnknownFingerprint(t *testing.T) {
	_, err := NewAnyTLSClient(context.Background(), AnyTLSConfig{Address: "example.com:443", Password: "secret", Fingerprint: "not-a-browser"})
	if err == nil {
		t.Fatal("unknown fingerprint silently ignored")
	}
}
