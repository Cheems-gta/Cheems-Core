package mobilebridge

import (
	"net"
	"strings"
	"testing"
	"time"
)

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
