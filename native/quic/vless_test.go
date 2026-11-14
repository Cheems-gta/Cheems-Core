package quictransport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

const testVLESSUUID = "00112233-4455-6677-8899-aabbccddeeff"

type vlessTestNetwork struct{}

func (vlessTestNetwork) Protect(int64) bool { return true }
func (vlessTestNetwork) Resolve(host string) (string, error) {
	if host == "vless.test" {
		return "127.0.0.1", nil
	}
	return "", net.InvalidAddrError("unexpected test hostname")
}

func TestVLESSRequestEncodesUserAndTCPDestination(t *testing.T) {
	user, err := parseVLESSUUID(testVLESSUUID)
	if err != nil {
		t.Fatal(err)
	}
	request, err := vlessRequest(user, 443, 2, []byte("target.test"))
	if err != nil {
		t.Fatal(err)
	}
	if request[0] != 0 || string(request[1:17]) != string(user[:]) || request[17] != 0 || request[18] != 1 {
		t.Fatalf("invalid VLESS version, UUID or command: %x", request[:19])
	}
	if binary.BigEndian.Uint16(request[19:21]) != 443 || request[21] != 2 || request[22] != byte(len("target.test")) {
		t.Fatalf("invalid VLESS port/address header: %x", request[:23])
	}
	if got := string(request[23:]); got != "target.test" {
		t.Fatalf("domain = %q", got)
	}
}

func TestVLESSClientTLSAuthAndTCPStream(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	cert := fixture.TLS.Certificates[0]
	fixture.Close()
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(plain, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				tlsConn := conn.(*tls.Conn)
				if tlsConn.Handshake() != nil {
					return
				}
				var prefix [23]byte
				if _, err := io.ReadFull(tlsConn, prefix[:]); err != nil {
					return
				}
				if prefix[0] != 0 || string(prefix[1:17]) != "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff" || prefix[18] != 1 {
					return
				}
				if prefix[21] != 2 {
					return
				}
				domain := make([]byte, int(prefix[22]))
				if _, err := io.ReadFull(tlsConn, domain); err != nil || string(domain) != "echo.test" {
					return
				}
				_, _ = tlsConn.Write([]byte{0, 0})
				buffer := make([]byte, 1024)
				for {
					n, err := tlsConn.Read(buffer)
					if n > 0 {
						if _, e := tlsConn.Write(buffer[:n]); e != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	client, err := NewVLESSClient(VLESSConfig{
		Address:    net.JoinHostPort("vless.test", strconv.Itoa(int(listener.Addr().(*net.TCPAddr).AddrPort().Port()))),
		ServerName: "example.com", UUID: testVLESSUUID, Network: vlessTestNetwork{},
		TrustedCAPEM: string(certificatePEM), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	stream, err := client.OpenTCP(context.Background(), "echo.test", 443)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if deadline, ok := stream.(interface{ SetDeadline(time.Time) error }); ok {
		_ = deadline.SetDeadline(time.Now().Add(5 * time.Second))
	}
	want := []byte("VLESS TLS TCP round trip")
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

func TestVLESSRejectsInvalidUUIDAndUntrustedTLS(t *testing.T) {
	if _, err := parseVLESSUUID("not-a-uuid"); err == nil {
		t.Fatal("invalid UUID accepted")
	}
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	address := fixture.Listener.Addr().String()
	fixture.Close()
	client, err := NewVLESSClient(VLESSConfig{Address: address, ServerName: "wrong.example", UUID: testVLESSUUID, Network: vlessTestNetwork{}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.OpenTCP(context.Background(), "echo.test", 443); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
}
