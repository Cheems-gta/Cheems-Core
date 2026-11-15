package quictransport

import (
	"context"
	"encoding/binary"
	"encoding/pem"
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

func TestVMessAndVLESSOverGRPC(t *testing.T) {
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
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.ProtoMajor != 2 || r.URL.Path != "/proxy/Tun" {
					http.Error(w, "bad tunnel", 400)
					return
				}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				go func() {
					defer a.Close()
					a.SetDeadline(time.Now().Add(3 * time.Second))
					if protocol == "vmess" {
						service.NewConnection(context.Background(), a, M.Socksaddr{}, nil)
						return
					}
					header := make([]byte, 23)
					if _, e := io.ReadFull(a, header); e != nil {
						return
					}
					if header[21] != 2 {
						return
					}
					if _, e := io.CopyN(io.Discard, a, int64(header[22])); e != nil {
						return
					}
					if _, e := a.Write([]byte{0, 0}); e != nil {
						return
					}
					io.Copy(a, a)
				}()
				go func() {
					defer b.Close()
					for {
						var header [5]byte
						if _, e := io.ReadFull(r.Body, header[:]); e != nil {
							return
						}
						size := binary.BigEndian.Uint32(header[1:])
						if header[0] != 0 || size > 1024*1024 {
							return
						}
						message := make([]byte, size)
						if _, e := io.ReadFull(r.Body, message); e != nil || len(message) < 2 || message[0] != 10 {
							return
						}
						length, n := binary.Uvarint(message[1:])
						if n < 1 || length != uint64(len(message)-n-1) {
							return
						}
						if _, e := b.Write(message[n+1:]); e != nil {
							return
						}
					}
				}()
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status")
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				buffer := make([]byte, 4096)
				for {
					n, e := b.Read(buffer)
					if n > 0 {
						var size [10]byte
						k := binary.PutUvarint(size[:], uint64(n))
						message := append([]byte{10}, size[:k]...)
						message = append(message, buffer[:n]...)
						frame := make([]byte, 5)
						binary.BigEndian.PutUint32(frame[1:], uint32(len(message)))
						frame = append(frame, message...)
						if _, e = w.Write(frame); e != nil {
							return
						}
						w.(http.Flusher).Flush()
					}
					if e != nil {
						w.Header().Set("Grpc-Status", "0")
						return
					}
				}
			}))
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			address := strings.TrimPrefix(server.URL, "https://")
			ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
			grpc := &GRPCConfig{ServiceName: "proxy", Authority: address}
			var client interface {
				OpenTCP(context.Context, string, int) (io.ReadWriteCloser, error)
				Close() error
			}
			var e error
			if protocol == "vmess" {
				client, e = NewVMessClient(VMessConfig{Address: address, ServerName: "127.0.0.1", UserID: testVMessUUID, Security: "aes-128-gcm", TLS: true, TrustedCAPEM: ca, Network: &testNetwork{allow: true}, GRPC: grpc})
			} else {
				client, e = NewVLESSClient(VLESSConfig{Address: address, ServerName: "127.0.0.1", UUID: testVMessUUID, TrustedCAPEM: ca, Network: &testNetwork{allow: true}, GRPC: grpc})
			}
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			conn, e := client.OpenTCP(ctx, "echo.invalid", 443)
			if e != nil {
				t.Fatal(e)
			}
			defer conn.Close()
			conn.(net.Conn).SetDeadline(time.Now().Add(3 * time.Second))
			if _, e = conn.Write([]byte("hello")); e != nil {
				t.Fatal(e)
			}
			got := make([]byte, 5)
			if _, e = io.ReadFull(conn, got); e != nil {
				t.Fatal(e)
			}
			if string(got) != "hello" {
				t.Fatal("bad echo")
			}
		})
	}
}
