package mobilebridge

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type staticTCPBackend struct{ id int }

func (staticTCPBackend) OpenTCP(context.Context, string, int) (io.ReadWriteCloser, error) {
	return nil, errors.New("test backend")
}

func TestTunnelBackendValidationAcceptsAnyNativeTCPBackend(t *testing.T) {
	old := activeTCP
	defer func() { activeTCP = old }()
	backend := staticTCPBackend{id: 1}
	mu.Lock()
	activeTCP = backend
	mu.Unlock()
	if !tunnelBackendStillActive(backend) {
		t.Fatal("active AnyTLS/VLESS-compatible TCP backend was rejected")
	}
	if tunnelBackendStillActive(staticTCPBackend{id: 2}) {
		t.Fatal("stale TCP backend was accepted")
	}
}

type cancelNetwork struct{ protected chan struct{} }

func (n *cancelNetwork) Protect(fd int64) bool {
	select {
	case n.protected <- struct{}{}:
	default:
	}
	return true
}
func (n *cancelNetwork) Resolve(host string) (string, error) { return "127.0.0.1", nil }

func TestStopCancelsInProgressQUICHandshake(t *testing.T) {
	Stop()
	defer Stop()
	// Keep the UDP destination bound but send no handshake response.
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	n := &cancelNetwork{protected: make(chan struct{}, 1)}
	done := make(chan error, 1)
	go func() {
		done <- StartWithNetwork("127.0.0.1", peer.LocalAddr().(*net.UDPAddr).Port, "localhost", "secret", 10991, strings.Repeat("a", 32), false, "", "", n)
	}()
	select {
	case <-n.protected:
	case err := <-done:
		t.Fatalf("startup exited too early: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("startup never reached the protected socket")
	}
	Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled startup succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop left the handshake blocked")
	}
	if IsRunning() {
		t.Fatal("canceled session reported running")
	}
}

func TestTUICBackendStartStop(t *testing.T) {
	Stop()
	defer Stop()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	network := &cancelNetwork{protected: make(chan struct{}, 1)}
	if err = StartTUICWithNetwork("127.0.0.1", 443, "localhost", "d342d11e-d424-4583-b36b-524ab1f0afa4", "password", "cubic", "h3", false, port, strings.Repeat("s", 32), "", network); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	registered := activeTCP != nil && activeUDP != nil && tuicClient != nil
	mu.Unlock()
	if !registered {
		t.Fatal("TUIC TCP and UDP backend registration missing")
	}
	Stop()
	mu.Lock()
	cleared := activeTCP == nil && activeUDP == nil && tuicClient == nil
	mu.Unlock()
	if !cleared || IsRunning() {
		t.Fatal("TUIC backend survived stop")
	}
}
