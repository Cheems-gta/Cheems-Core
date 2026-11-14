package quictransport

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type shadowsocks2022TestNetwork struct{ protected int }

func (n *shadowsocks2022TestNetwork) Protect(fd int64) bool {
	n.protected++
	return fd >= 0
}
func (*shadowsocks2022TestNetwork) Resolve(host string) (string, error) {
	return "", net.InvalidAddrError("unexpected resolve: " + host)
}

type shadowsocks2022EchoHandler struct{}

func (shadowsocks2022EchoHandler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error {
	defer conn.Close()
	_, err := io.Copy(conn, conn)
	return err
}
func (shadowsocks2022EchoHandler) NewPacket(context.Context, N.PacketConn, *buf.Buffer, M.Metadata) error {
	return nil
}
func (shadowsocks2022EchoHandler) NewPacketConnection(context.Context, N.PacketConn, M.Metadata) error {
	return nil
}
func (shadowsocks2022EchoHandler) NewError(context.Context, error) {}

func startShadowsocks2022Echo(t *testing.T, listener net.Listener, method string, key []byte) {
	t.Helper()
	service, err := shadowaead_2022.NewService(method, key, int64(60), shadowsocks2022EchoHandler{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) { _ = service.NewConnection(context.Background(), c, M.Metadata{}) }(conn)
		}
	}()
}

func TestShadowsocks2022AEADRoundTripThroughProtectedSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	key := []byte("0123456789abcdef")
	method := "2022-blake3-aes-128-gcm"
	startShadowsocks2022Echo(t, listener, method, key)

	network := &shadowsocks2022TestNetwork{}
	client, err := NewShadowsocks2022Client(Shadowsocks2022Config{
		Address: listener.Addr().String(), Method: method,
		Password: base64.StdEncoding.EncodeToString(key), Timeout: time.Second,
		Network: network,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenTCP(context.Background(), "example.com", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err = stream.Write([]byte("ss2022-roundtrip")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("ss2022-roundtrip"))
	if _, err = io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "ss2022-roundtrip" {
		t.Fatalf("unexpected echo: %q", got)
	}
	if network.protected != 1 {
		t.Fatalf("protected sockets = %d, want 1", network.protected)
	}
}

func TestShadowsocks2022RejectsInvalidKeysAndMethods(t *testing.T) {
	for _, cfg := range []Shadowsocks2022Config{
		{Address: "127.0.0.1:443", Method: "aes-256-gcm", Password: "abc", Network: &shadowsocks2022TestNetwork{}},
		{Address: "127.0.0.1:443", Method: "2022-blake3-aes-128-gcm", Password: base64.StdEncoding.EncodeToString([]byte("short")), Network: &shadowsocks2022TestNetwork{}},
		{Address: "127.0.0.1:443", Method: "2022-blake3-aes-128-gcm", Password: base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))},
	} {
		if _, err := NewShadowsocks2022Client(cfg); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
}
