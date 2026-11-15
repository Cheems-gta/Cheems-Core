package mobilebridge

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	quictransport "github.com/Cheems-gta/Cheems-Core/native/quic"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

type dnsWriteback struct{ packets chan []byte }

func (*dnsWriteback) ReturnHeadroom() int { return 0 }
func (w *dnsWriteback) WriteReturnPackets(packets [][]byte) error {
	for _, p := range packets {
		w.packets <- append([]byte(nil), p...)
	}
	return nil
}

type dnsTCPBackend struct{ targets chan string }

func (b dnsTCPBackend) OpenTCP(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	b.targets <- net.JoinHostPort(host, "53")
	a, c := net.Pipe()
	go func() {
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		var size [2]byte
		if _, e := io.ReadFull(c, size[:]); e != nil {
			return
		}
		query := make([]byte, int(binary.BigEndian.Uint16(size[:])))
		if _, e := io.ReadFull(c, query); e != nil {
			return
		}
		query[2] |= 0x80
		c.Write(append(size[:], query...))
	}()
	return a, nil
}

type dnsUDPBackend struct{ fallback bool }

func (b dnsUDPBackend) OpenUDPAssociation(destination string) (udpAssociation, error) {
	if b.fallback {
		return nil, errors.New("UDP not supported")
	}
	return &dnsUDPAssociation{}, nil
}

type dnsUDPAssociation struct{ query []byte }

func (a *dnsUDPAssociation) WriteTo(query []byte, destination string) error {
	if destination != "1.1.1.1:53" {
		return errors.New("wrong DNS upstream")
	}
	a.query = append([]byte(nil), query...)
	return nil
}
func (a *dnsUDPAssociation) Read(context.Context) (quictransport.UDPMessage, error) {
	a.query[2] |= 0x80
	return quictransport.UDPMessage{Address: "1.1.1.1:53", Payload: a.query}, nil
}
func (*dnsUDPAssociation) Close() error { return nil }

func TestVirtualDNSPacketsTraverseDispatcherAndReturnFromOriginalAddress(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, fallback := range []bool{false, true} {
			name := "IPv4 UDP"
			if v6 {
				name = "IPv6 UDP"
			}
			if fallback {
				name += " to TCP fallback"
			}
			t.Run(name, func(t *testing.T) {
				source := netip.MustParseAddr("10.77.0.1")
				destination := netip.MustParseAddr("10.77.0.2")
				headerLength := 20
				if v6 {
					source = netip.MustParseAddr("fd77:77::1")
					destination = netip.MustParseAddr("fd77:77::2")
					headerLength = 40
				}
				query := []byte{0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
				packet := make([]byte, headerLength+8+len(query))
				if v6 {
					packet[0] = 0x60
					binary.BigEndian.PutUint16(packet[4:], uint16(8+len(query)))
					packet[6] = 17
					packet[7] = 64
					copy(packet[8:24], source.AsSlice())
					copy(packet[24:40], destination.AsSlice())
				} else {
					packet[0] = 0x45
					binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
					packet[8] = 64
					packet[9] = 17
					copy(packet[12:16], source.AsSlice())
					copy(packet[16:20], destination.AsSlice())
				}
				udp := packet[headerLength:]
				binary.BigEndian.PutUint16(udp, 40000)
				binary.BigEndian.PutUint16(udp[2:], 53)
				binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
				copy(udp[8:], query)
				targets := make(chan string, 1)
				handler := &vpnFlowHandler{tcp: dnsTCPBackend{targets}, udp: dnsUDPBackend{fallback}, dnsGate: make(chan struct{}, 1)}
				writer := &dnsWriteback{make(chan []byte, 1)}
				resume := make(chan struct{}, 1)
				dispatcher := tun.NewForwardDispatcher(handler, writer, logger.NOP(), 1500, tun.UDPNatOptions{}, time.Minute)
				defer dispatcher.Close()
				stage := dispatcher.NewStage(writer, func() { resume <- struct{}{} })
				if !stage.Dispatch(packet) {
					t.Fatal("DNS packet not dispatched")
				}
				select {
				case <-resume:
				case <-time.After(time.Second):
					t.Fatal("flow judgement did not complete")
				}
				leaked := false
				stage.ResumeJudged(func([]byte, tun.ForwardFrameMeta) { leaked = true })
				if leaked {
					t.Fatal("virtual DNS escaped into ordinary proxy UDP")
				}
				select {
				case response := <-writer.packets:
					var got netip.Addr
					if v6 {
						var a [16]byte
						copy(a[:], response[8:24])
						got = netip.AddrFrom16(a)
					} else {
						got = netip.AddrFrom4([4]byte(response[12:16]))
					}
					if got != destination {
						t.Fatalf("DNS reply came from %s instead of queried virtual address %s", got, destination)
					}
					if binary.BigEndian.Uint16(response[headerLength:]) != 53 || binary.BigEndian.Uint16(response[headerLength+2:]) != 40000 {
						t.Fatal("wrong DNS response ports")
					}
					payload := response[headerLength+8:]
					if !matchingDNSResponse(query, payload) {
						t.Fatal("wrong DNS response")
					}
				case <-time.After(2 * time.Second):
					t.Fatal("no DNS reply returned to TUN")
				}
				if fallback {
					select {
					case target := <-targets:
						if target != "1.1.1.1:53" {
							t.Fatal("TCP DNS escaped selected backend")
						}
					default:
						t.Fatal("TCP fallback not used")
					}
				}
			})
		}
	}
}

func TestTCPVirtualDNSUsesSelectedNodeResolver(t *testing.T) {
	targets := make(chan string, 1)
	handler := &vpnFlowHandler{tcp: dnsTCPBackend{targets}, metrics: &tunnelMetrics{}}
	client, server := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		handler.NewConnectionEx(context.Background(), server, M.ParseSocksaddr("10.77.0.1:40000"), M.ParseSocksaddr("10.77.0.2:53"), nil)
		close(done)
	}()
	query := []byte{0, 12, 0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, e := client.Write(query); e != nil {
		t.Fatal(e)
	}
	response := make([]byte, len(query))
	if _, e := io.ReadFull(client, response); e != nil {
		t.Fatal(e)
	}
	if response[4]&0x80 == 0 {
		t.Fatal("missing DNS response")
	}
	if target := <-targets; target != "1.1.1.1:53" {
		t.Fatalf("wrong target %s", target)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP DNS flow not cleaned up")
	}
}
func TestOldTunnelMetricsDoNotModifyNewSession(t *testing.T) {
	old := resetTunnelDiagnostics()
	h := &vpnFlowHandler{metrics: old}
	resetTunnelDiagnostics()
	old.up.Add(123)
	h.recordError("DNS", io.EOF)
	if TunnelUploaded() != 0 || TunnelLastError() != "" {
		t.Fatal("stopped session polluted successor diagnostics")
	}
}
