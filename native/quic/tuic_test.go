package quictransport

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/logger"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTUICVerifiedTCPAndUDP(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.Certificate().Raw})
	fixture.Close()
	socket, e := net.ListenPacket("udp4", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	id, _ := parseVLESSUUID(testVMessUUID)
	service, e := tuic.NewService[string](tuic.ServiceOptions{Context: context.Background(), Logger: logger.NOP(), TLSConfig: &tuicTLSConfig{&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}}, Handler: vmessEchoHandler{}, AuthTimeout: time.Second, UDPTimeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	service.UpdateUsers([]string{"user"}, [][16]byte{id}, []string{"password"})
	if e = service.Start(socket); e != nil {
		t.Fatal(e)
	}
	defer service.Close()
	cfg := TUICConfig{Address: socket.LocalAddr().String(), ServerName: "127.0.0.1", UUID: testVMessUUID, Password: "password", TrustedCAPEM: string(ca), Network: &testNetwork{allow: true}}
	t.Run("TCP", func(t *testing.T) {
		c, e := NewTUICClient(cfg)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, e := c.OpenTCP(ctx, "echo.invalid", 443)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		conn.(net.Conn).SetDeadline(time.Now().Add(3 * time.Second))
		if _, e = conn.Write([]byte("hello")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 5)
		if _, e = io.ReadFull(conn, b); e != nil {
			t.Fatal(e)
		}
		if string(b) != "hello" {
			t.Fatal("bad TCP echo")
		}
	})
	for _, stream := range []bool{false, true} {
		name := "UDP datagrams"
		if stream {
			name = "UDP streams"
		}
		t.Run(name, func(t *testing.T) {
			local := cfg
			local.UDPStream = stream
			c, e := NewTUICClient(local)
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			a, e := c.OpenUDPAssociation()
			if e != nil {
				t.Fatal(e)
			}
			defer a.Close()
			if e = a.WriteTo([]byte("hello"), "echo.invalid:53"); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			m, e := a.Read(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if string(m.Payload) != "hello" || m.Address != "echo.invalid:53" {
				t.Fatalf("bad UDP echo: %+v", m)
			}
		})
	}
	t.Run("reject unknown root", func(t *testing.T) {
		local := cfg
		local.TrustedCAPEM = ""
		c, e := NewTUICClient(local)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if conn, e := c.OpenTCP(ctx, "echo.invalid", 443); e == nil {
			conn.Close()
			t.Fatal("accepted unknown TLS root")
		}
	})
	t.Run("reject password", func(t *testing.T) {
		local := cfg
		local.Password = "wrong"
		c, e := NewTUICClient(local)
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		conn, e := c.OpenTCP(ctx, "echo.invalid", 443)
		if e != nil {
			return
		}
		defer conn.Close()
		conn.(net.Conn).SetDeadline(time.Now().Add(3 * time.Second))
		_, e = conn.Write([]byte("hello"))
		if e == nil {
			b := make([]byte, 5)
			_, e = io.ReadFull(conn, b)
		}
		if e == nil {
			t.Fatal("wrong password delivered data")
		}
	})
}
