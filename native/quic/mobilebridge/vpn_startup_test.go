//go:build linux

package mobilebridge

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestTunnelStartupHandlesUnavailableOffloadQuery(t *testing.T) {
	Stop()
	defer Stop()
	// A datagram pair reproduces an unavailable TUNGETIFF query without root.
	// Android drivers may deny this optional offload probe; it must not panic.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	mu.Lock()
	activeTCP = staticTCPBackend{id: 9}
	startNetwork = &cancelNetwork{protected: make(chan struct{}, 1)}
	mu.Unlock()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("optional TUN probe crashed: %v", recovered)
		}
	}()
	if err := StartTunnel(int64(fds[0])); err != nil {
		t.Fatal(err)
	}
	StopTunnel()
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("tunnel closed the Android-owned original descriptor: %v", err)
	}
}
