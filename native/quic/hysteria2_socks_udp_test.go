package quictransport

import (
	"bytes"
	"net"
	"testing"
)

func TestSOCKS5UDPAddressRoundTrip(t *testing.T) {
	for _, address := range []string{"192.0.2.1:53", "[2001:db8::53]:443", "dns.example:5353"} {
		frame, err := marshalSOCKSUDP(address, []byte("packet"))
		if err != nil {
			t.Fatal(err)
		}
		got, payload, err := parseSOCKSUDP(frame)
		if err != nil {
			t.Fatal(err)
		}
		if got != address || !bytes.Equal(payload, []byte("packet")) {
			t.Fatalf("round trip %q %q", got, payload)
		}
	}
}

func TestSOCKS5UDPRejectsMalformedAndFragmentedPackets(t *testing.T) {
	for _, frame := range [][]byte{{}, {0, 0, 1, 1, 1, 2, 3, 4, 0, 53}, {0, 0, 0, 1, 1, 2, 3, 4, 0, 0}, {0, 0, 0, 3, 0, 0, 53}, {0, 0, 0, 9}} {
		if _, _, err := parseSOCKSUDP(frame); err == nil {
			t.Fatalf("accepted malformed SOCKS UDP frame %x", frame)
		}
	}
}

func TestSOCKSUDPReplyAddressFamily(t *testing.T) {
	for _, ip := range []net.IP{net.IPv4(127, 0, 0, 1), net.ParseIP("::1")} {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(ip.String(), "1234"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := marshalSOCKSUDP(net.JoinHostPort(ip.String(), "1234"), nil)
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := parseSOCKSUDP(b)
		if err != nil || got != net.JoinHostPort(ip.String(), "1234") {
			t.Fatalf("%v %q", err, got)
		}
		_ = addr
	}
}
