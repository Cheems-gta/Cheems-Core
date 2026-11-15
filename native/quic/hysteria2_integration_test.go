package quictransport

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"
)

// A separate HTTP/3 peer parses the HY2 request itself. This exercises actual
// QUIC, verified TLS, authentication and a bidirectional proxy stream.
func TestProtectedHysteria2EndToEnd(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw})
	fixture.Close()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	server := &http3.Server{
		TLSConfig:       fixture.TLS.Clone(),
		EnableDatagrams: true,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != "secret" {
				w.WriteHeader(403)
				return
			}
			w.Header().Set("Hysteria-UDP", "true")
			w.WriteHeader(233)
		}),
	}
	server.TLSConfig.Certificates = []tls.Certificate{cert}
	handleHY2Stream := func(s *quic.Stream) {
		kind, e := quicvarint.Read(unbufferedVarintReader{s})
		if e != nil || kind != 0x401 {
			s.CancelRead(1)
			return
		}
		func() {
			defer s.Close()
			_ = s.SetDeadline(time.Now().Add(5 * time.Second))
			reader := unbufferedVarintReader{s}
			size, e := quicvarint.Read(reader)
			if e != nil || size > 2048 {
				return
			}
			target := make([]byte, int(size))
			if _, e = io.ReadFull(s, target); e != nil || string(target) != "echo.invalid:80" {
				return
			}
			padding, e := quicvarint.Read(reader)
			if e != nil || padding > 4096 {
				return
			}
			if _, e = io.CopyN(io.Discard, s, int64(padding)); e != nil {
				return
			}
			if _, e = s.Write([]byte{0, 0, 0}); e != nil {
				return
			}
			payload := make([]byte, 5)
			if _, e = io.ReadFull(s, payload); e == nil {
				_, _ = s.Write(payload)
			}
		}()
	}

	defer server.Close()
	listener, err := quic.Listen(packet, http3.ConfigureTLSConfig(server.TLSConfig), &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept(context.Background())
			if e != nil {
				return
			}
			go func() {
				raw, e := server.NewRawServerConn(conn)
				if e != nil {
					return
				}
				go func() {
					for {
						stream, e := conn.AcceptUniStream(context.Background())
						if e != nil {
							return
						}
						go raw.HandleUnidirectionalStream(stream)
					}
				}()
				auth, e := conn.AcceptStream(context.Background())
				if e != nil {
					return
				}
				go raw.HandleRequestStream(auth)
				for {
					stream, e := conn.AcceptStream(context.Background())
					if e != nil {
						return
					}
					go handleHY2Stream(stream)
				}
			}()
		}
	}()
	n := &testNetwork{ip: "127.0.0.1", allow: true}
	port := packet.LocalAddr().(*net.UDPAddr).Port
	cfg := Hysteria2Config{Address: net.JoinHostPort("edge.invalid", strconv.Itoa(port)), ServerName: "127.0.0.1", Password: "secret", TrustedCAPEM: string(ca), Network: n}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	session, err := DialHysteria2(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	stream, err := session.OpenTCP(ctx, "echo.invalid", 80)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 5)
	if _, err = io.ReadFull(stream, reply); err != nil || string(reply) != "hello" {
		t.Fatalf("echo %q: %v", reply, err)
	}
	if n.protected.Load() != 1 {
		t.Fatal("upstream socket was not protected")
	}
	if err = session.Close(); err != nil {
		t.Fatal(err)
	}
	if err = session.Close(); err != nil {
		t.Fatal("repeated close failed", err)
	}
	if _, err = session.Transport.packet.WriteTo([]byte("closed"), packet.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("UDP socket leaked: %v", err)
	}
	cfg.Password = "wrong"
	if rejected, e := DialHysteria2(ctx, cfg); e == nil {
		rejected.Close()
		t.Fatal("accepted wrong password")
	} else if !strings.Contains(e.Error(), "403") {
		t.Fatalf("unexpected auth failure: %v", e)
	}
}
