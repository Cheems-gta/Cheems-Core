package quictransport

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

type testNetwork struct {
	ip         string
	resolveErr error
	allow      bool
	protected  atomic.Int32
	resolved   atomic.Int32
}

func (n *testNetwork) Protect(fd int64) bool {
	n.protected.Add(1)
	return fd >= 0 && n.allow
}
func (n *testNetwork) Resolve(host string) (string, error) {
	n.resolved.Add(1)
	return n.ip, n.resolveErr
}

func TestProtectedSocketRejectsBeforeSending(t *testing.T) {
	n := &testNetwork{ip: "127.0.0.1"}
	p, _, err := protectedPacket(context.Background(), "edge.invalid:443", n)
	if p != nil {
		p.Close()
		t.Fatal("rejected socket remained open")
	}
	if err == nil || !strings.Contains(err.Error(), "protection rejected") {
		t.Fatalf("expected protection rejection: %v", err)
	}
	if n.protected.Load() != 1 || n.resolved.Load() != 1 {
		t.Fatal("missing platform callbacks")
	}
}

func TestPhysicalResolverFailureNeverFallsBack(t *testing.T) {
	for _, n := range []*testNetwork{
		{resolveErr: errors.New("offline")},
		{ip: "another-host.invalid"},
	} {
		p, _, err := protectedPacket(context.Background(), "localhost:443", n)
		if p != nil {
			p.Close()
			t.Fatal("unexpected socket after resolver failure")
		}
		if err == nil || n.protected.Load() != 0 {
			t.Fatal("physical DNS failure was ignored")
		}
	}
}

func TestLiteralUpstreamUsesProtectionWithoutDNS(t *testing.T) {
	n := &testNetwork{allow: true}
	p, remote, err := protectedPacket(context.Background(), "127.0.0.1:443", n)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if !remote.IP.Equal(net.ParseIP("127.0.0.1")) || n.resolved.Load() != 0 || n.protected.Load() != 1 {
		t.Fatal("literal address routing mismatch")
	}
}
