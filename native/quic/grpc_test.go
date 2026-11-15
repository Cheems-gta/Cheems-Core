package quictransport

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestGRPCTransportMatchesIndependentHunkVectors(t *testing.T) {
	received := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 || r.URL.Path != "/proxy.Service/Tun" || r.Header.Get("Content-Type") != "application/grpc" {
			http.Error(w, "bad grpc request", 400)
			return
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		expected := []byte{0, 0, 0, 0, 7, 10, 5, 'h', 'e', 'l', 'l', 'o'}
		got := make([]byte, len(expected))
		_, e := io.ReadFull(r.Body, got)
		if e == nil && !bytes.Equal(got, expected) {
			e = io.ErrUnexpectedEOF
		}
		received <- e
		w.Write([]byte{0, 0, 0, 0, 7, 10, 5, 'w', 'o', 'r', 'l', 'd'})
		w.(http.Flusher).Flush()
		w.Header().Set("Grpc-Status", "0")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	address := strings.TrimPrefix(server.URL, "https://")
	raw, e := tls.Dial("tcp", address, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1", NextProtos: []string{"h2"}})
	if e != nil {
		t.Fatal(e)
	}
	raw.SetDeadline(time.Now().Add(3 * time.Second))
	stream, e := wrapGRPC(raw, GRPCConfig{ServiceName: "proxy.Service", Authority: address})
	if e != nil {
		t.Fatal(e)
	}
	defer stream.Close()
	if _, e = stream.Write([]byte("hello")); e != nil {
		t.Fatal(e)
	}
	got := make([]byte, 5)
	if _, e = io.ReadFull(stream, got); e != nil {
		t.Fatal(e)
	}
	if string(got) != "world" {
		t.Fatalf("bad payload %q", got)
	}
	if e = <-received; e != nil {
		t.Fatal(e)
	}
	if _, e = stream.Read(got); e != io.EOF {
		t.Fatalf("stream end: %v", e)
	}
}
func TestGRPCRejectsInvalidConfig(t *testing.T) {
	for _, c := range []GRPCConfig{{ServiceName: "../proxy", Authority: "test"}, {ServiceName: "proxy", Authority: "bad/path"}, {ServiceName: "", Authority: "test"}} {
		if c.validate() == nil {
			t.Fatalf("accepted %+v", c)
		}
	}
	_, e := NewVMessClient(VMessConfig{Address: "127.0.0.1:443", UserID: testVMessUUID, Security: "auto", Network: &testNetwork{allow: true}, GRPC: &GRPCConfig{ServiceName: "proxy", Authority: "test"}})
	if e == nil {
		t.Fatal("accepted grpc without TLS")
	}
}
