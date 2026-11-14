package mobilebridge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/sys/unix"
)

var tunnelState struct {
	sync.Mutex
	device tun.Tun
	stack  tun.Stack
	cancel context.CancelFunc
}

// StartTunnel attaches Android's established VPN descriptor to the Go TCP/IP
// stack. The fd is duplicated because the stack takes ownership of its copy.
func StartTunnel(fd int64) error {
	if fd < 0 || fd > int64(^uint(0)>>1) {
		return errors.New("invalid TUN file descriptor")
	}
	mu.Lock()
	current, datagrams, network := activeTCP, activeUDP, startNetwork
	mu.Unlock()
	if current == nil || network == nil {
		return errors.New("authenticated TCP proxy session with protected physical network required")
	}
	tunnelState.Lock()
	defer tunnelState.Unlock()
	if tunnelState.stack != nil {
		return errors.New("VPN tunnel already running")
	}
	owned, err := unix.Dup(int(fd))
	if err != nil {
		return err
	}
	options := tun.Options{
		Name: "cheems", FileDescriptor: owned, MTU: 1500,
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("10.77.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd77:77::1/126")},
		DNSAddress:   []netip.Addr{netip.MustParseAddr("10.77.0.2"), netip.MustParseAddr("fd77:77::2")},
		DNSMode:      tun.DNSModeHijack, EXP_ExternalConfiguration: true,
	}
	device, err := tun.New(options)
	if err != nil {
		_ = unix.Close(owned)
		return err
	}
	if err = device.Start(); err != nil {
		_ = device.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	handler := &vpnFlowHandler{tcp: current, udp: datagrams}
	stack, err := tun.NewStack("go", tun.StackOptions{Context: ctx, Tun: device, TunOptions: options, Handler: handler, UDPTimeout: 2 * time.Minute, ICMPTimeout: time.Minute})
	if err != nil {
		cancel()
		_ = device.Close()
		return err
	}
	if err = stack.Start(); err != nil {
		cancel()
		_ = stack.Close()
		_ = device.Close()
		return err
	}
	stillCurrent := tunnelBackendStillActive(current)
	if !stillCurrent {
		cancel()
		_ = stack.Close()
		_ = device.Close()
		return errors.New("native TCP backend changed while VPN tunnel started")
	}
	tunnelState.device, tunnelState.stack, tunnelState.cancel = device, stack, cancel
	return nil
}

func tunnelBackendStillActive(candidate tcpBackend) bool {
	mu.Lock()
	defer mu.Unlock()
	return candidate != nil && activeTCP == candidate
}

// StopTunnel closes the TUN stack before releasing its duplicated descriptor.
func StopTunnel() {
	tunnelState.Lock()
	stack, device, cancel := tunnelState.stack, tunnelState.device, tunnelState.cancel
	tunnelState.stack, tunnelState.device, tunnelState.cancel = nil, nil, nil
	tunnelState.Unlock()
	if cancel != nil {
		cancel()
	}
	if stack != nil {
		_ = stack.Close()
	}
	if device != nil {
		_ = device.Close()
	}
}

type vpnFlowHandler struct {
	tcp tcpBackend
	udp udpBackend
}

func (h *vpnFlowHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *vpnFlowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	upstream, err := h.tcp.OpenTCP(ctx, destination.AddrString(), int(destination.Port))
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, conn)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, upstream)
	_ = conn.Close()
	<-done
}

func (h *vpnFlowHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	if h.udp == nil {
		return
	}
	assoc, err := h.udp.OpenUDPAssociation(destination.String())
	if err != nil {
		return
	}
	defer assoc.Close()
	go func() {
		for {
			packet := buf.NewSize(65535)
			target, e := conn.ReadPacket(packet)
			if e != nil {
				packet.Release()
				return
			}
			payload := append([]byte(nil), packet.Bytes()...)
			packet.Release()
			if e = assoc.WriteTo(payload, target.String()); e != nil {
				return
			}
		}
	}()
	for {
		message, e := assoc.Read(ctx)
		if e != nil {
			break
		}
		target := M.ParseSocksaddr(message.Address)
		packet := buf.NewSize(len(message.Payload))
		_, _ = packet.Write(message.Payload)
		if e = conn.WritePacket(packet, target); e != nil {
			return
		}
	}
}

func (h *vpnFlowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if h.udp != nil {
		assoc, err := h.udp.OpenUDPAssociation("1.1.1.1:53")
		if err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err = assoc.WriteTo(payload, "1.1.1.1:53"); err == nil {
				response, readErr := assoc.Read(ctx)
				if readErr == nil {
					packet := buf.NewSize(len(response.Payload))
					_, _ = packet.Write(response.Payload)
					_ = writer.WritePacket(packet, M.ParseSocksaddr(response.Address))
					cancel()
					_ = assoc.Close()
					return
				}
			}
			cancel()
			_ = assoc.Close()
		}
	}
	response, err := dnsOverTCP(h.tcp, payload)
	if err != nil {
		return
	}
	packet := buf.NewSize(len(response))
	_, _ = packet.Write(response)
	_ = writer.WritePacket(packet, M.ParseSocksaddr("1.1.1.1:53"))
}

func dnsOverTCP(session tcpBackend, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("invalid DNS packet size")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := session.OpenTCP(ctx, "1.1.1.1", 53)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	deadline := time.AfterFunc(5*time.Second, func() { _ = stream.Close() })
	defer deadline.Stop()
	frame := make([]byte, len(query)+2)
	frame[0] = byte(len(query) >> 8)
	frame[1] = byte(len(query))
	copy(frame[2:], query)
	if _, err = stream.Write(frame); err != nil {
		return nil, err
	}
	var header [2]byte
	if _, err = io.ReadFull(stream, header[:]); err != nil {
		return nil, err
	}
	n := int(header[0])<<8 | int(header[1])
	if n == 0 {
		return nil, errors.New("empty DNS response")
	}
	response := make([]byte, n)
	_, err = io.ReadFull(stream, response)
	return response, err
}

var _ tun.Handler = (*vpnFlowHandler)(nil)
