package quictransport

import (
	"bytes"
	"net"
	"testing"
)

func TestHysteria2UDPMessageRoundTrip(t *testing.T) {
	input := UDPMessage{SessionID: 0x10203040, PacketID: 0x5060, Address: net.JoinHostPort("2001:db8::1", "5353"), Payload: []byte{0, 1, 2, 255}}
	frame, err := input.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(frame[:8], []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0, 1}) {
		t.Fatalf("bad Hysteria UDP fixed header: %x", frame[:8])
	}
	got, err := ParseUDPMessage(frame)
	if err != nil {
		t.Fatal(err)
	}
	if got.SessionID != input.SessionID || got.PacketID != input.PacketID || got.Address != input.Address || !bytes.Equal(got.Payload, input.Payload) {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestHysteria2UDPRejectsMalformedFrames(t *testing.T) {
	for _, frame := range [][]byte{
		{},
		{0, 0, 0, 0, 0, 1, 0, 1, 0},      // zero session
		{0, 0, 0, 1, 0, 1, 1, 1, 0},      // fragmented packet
		{0, 0, 0, 1, 0, 1, 0, 1, 255},    // truncated varint
		{0, 0, 0, 1, 0, 1, 0, 1, 3, 'x'}, // short address
	} {
		if _, err := ParseUDPMessage(frame); err == nil {
			t.Fatalf("accepted invalid datagram %x", frame)
		}
	}
}

func TestHysteria2UDPRejectsOversizeAndInvalidDestinations(t *testing.T) {
	for _, m := range []UDPMessage{
		{SessionID: 1, Address: "example.com:0"},
		{SessionID: 1, Address: "example.com:53", Payload: make([]byte, maxUDPMessageSize+1)},
		{SessionID: 1, Address: "bad address"},
	} {
		if _, err := m.MarshalBinary(); err == nil {
			t.Fatal("accepted invalid UDP message")
		}
	}
}
