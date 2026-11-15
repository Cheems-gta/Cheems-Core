package quictransport

import (
	"context"
	"encoding/pem"
	"github.com/gorilla/websocket"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestVMessAndVLESSOverVerifiedWebSocket(t *testing.T) {
	for _, protocol := range []string{"vmess", "vless"} {
		t.Run(protocol, func(t *testing.T) {
			service := vmess.NewService[string](vmessEchoHandler{})
			if e := service.UpdateUsers([]string{"test"}, []string{testVMessUUID}, []int{0}); e != nil {
				t.Fatal(e)
			}
			if e := service.Start(); e != nil {
				t.Fatal(e)
			}
			defer service.Close()
			peer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.RequestURI() != "/proxy?ed=0" || r.Host != "proxy.example" {
					http.Error(w, "bad upgrade target", 400)
					return
				}
				ws, e := (&websocket.Upgrader{}).Upgrade(w, r, nil)
				if e != nil {
					return
				}
				conn := &webSocketStream{Conn: ws.UnderlyingConn(), ws: ws}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if protocol == "vmess" {
					_ = service.NewConnection(context.Background(), conn, M.Socksaddr{}, nil)
					return
				}
				header := make([]byte, 19)
				if _, e = io.ReadFull(conn, header); e != nil {
					return
				}
				tail := make([]byte, 4)
				if _, e = io.ReadFull(conn, tail); e != nil {
					return
				}
				if tail[2] != 2 {
					return
				}
				name := make([]byte, int(tail[3]))
				if _, e = io.ReadFull(conn, name); e != nil {
					return
				}
				if _, e = conn.Write([]byte{0, 0}); e != nil {
					return
				}
				io.Copy(conn, conn)
			}))
			defer peer.Close()
			cfg := WebSocketConfig{Host: "proxy.example", Path: "/proxy?ed=0"}
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peer.Certificate().Raw}))
			address := strings.TrimPrefix(peer.URL, "https://")
			var c interface {
				OpenTCP(context.Context, string, int) (io.ReadWriteCloser, error)
				Close() error
			}
			var e error
			if protocol == "vmess" {
				c, e = NewVMessClient(VMessConfig{Address: address, ServerName: "127.0.0.1", UserID: testVMessUUID, Security: "aes-128-gcm", TLS: true, TrustedCAPEM: ca, Network: &testNetwork{allow: true}, WebSocket: &cfg})
			} else {
				c, e = NewVLESSClient(VLESSConfig{Address: address, ServerName: "127.0.0.1", UUID: testVMessUUID, TrustedCAPEM: ca, Network: &testNetwork{allow: true}, WebSocket: &cfg})
			}
			if e != nil {
				t.Fatal(e)
			}
			defer c.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			stream, e := c.OpenTCP(ctx, "echo.invalid", 443)
			if e != nil {
				t.Fatal(e)
			}
			defer stream.Close()
			stream.(net.Conn).SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = stream.Write([]byte("hello")); e != nil {
				t.Fatal(e)
			}
			b := make([]byte, 5)
			if _, e = io.ReadFull(stream, b); e != nil {
				t.Fatal(e)
			}
			if string(b) != "hello" {
				t.Fatal("bad echo")
			}
		})
	}
}
