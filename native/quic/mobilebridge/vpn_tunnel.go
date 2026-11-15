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
	"github.com/sagernet/sing/common/logger"
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
		Logger: logger.NOP(),
		Name:   "cheems", FileDescriptor: owned, MTU: 1500,
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
	metrics := resetTunnelDiagnostics()
	handler := &vpnFlowHandler{tcp: current, udp: datagrams, dnsGate: make(chan struct{}, 32), metrics: metrics, ctx: ctx}
	stack, err := tun.NewStack("go", tun.StackOptions{Context: ctx, Tun: device, TunOptions: options, Handler: handler, Logger: logger.NOP(), UDPTimeout: 2 * time.Minute, ICMPTimeout: time.Minute})
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
	ctx     context.Context
	tcp     tcpBackend
	udp     udpBackend
	dnsGate chan struct{}
	metrics *tunnelMetrics
}

func isVirtualDNS(destination netip.AddrPort) bool {
	return destination.Port() == 53 && (destination.Addr().Unmap() == netip.MustParseAddr("10.77.0.2") || destination.Addr() == netip.MustParseAddr("fd77:77::2"))
}
func (h *vpnFlowHandler) JudgeFlow(protocol uint8, _ netip.AddrPort, destination netip.AddrPort, _ []byte) tun.FlowVerdict {
	if protocol == 17 && isVirtualDNS(destination) {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (h *vpnFlowHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if onClose != nil {
		defer onClose(nil)
	}
	if isVirtualDNS(destination.AddrPort()) {
		destination = M.ParseSocksaddr("1.1.1.1:53")
	}
	h.metricsOrCurrent().active.Add(1)
	defer h.metricsOrCurrent().active.Add(-1)
	upstream, err := h.tcp.OpenTCP(ctx, destination.AddrString(), int(destination.Port))
	if err != nil {
		h.recordError("TCP 建连", err)
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(countedWriter{upstream, &h.metricsOrCurrent().up}, conn)
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(countedWriter{conn, &h.metricsOrCurrent().down}, upstream)
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
	h.metricsOrCurrent().active.Add(1)
	defer h.metricsOrCurrent().active.Add(-1)
	go func() {
		defer assoc.Close()
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
				h.recordError("UDP 发送", e)
				return
			}
			h.metricsOrCurrent().up.Add(int64(len(payload)))
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
		h.metricsOrCurrent().down.Add(int64(len(message.Payload)))
	}
}

func (h *vpnFlowHandler) NewDNSPacket(payload []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	if h.ctx != nil && h.ctx.Err() != nil {
		return
	}
	if len(payload) < 12 {
		return
	}
	if h.dnsGate != nil {
		select {
		case h.dnsGate <- struct{}{}:
		default:
			h.recordError("DNS 请求过多", errors.New("busy"))
			return
		}
	}
	query := append([]byte(nil), payload...)
	h.metricsOrCurrent().dns.Add(1)
	// sing-tun invokes this callback on its packet engine; network I/O must not block it.
	go func() {
		if h.dnsGate != nil {
			defer func() { <-h.dnsGate }()
		}
		h.forwardDNS(query, source, destination, writer)
	}()
}
func matchingDNSResponse(query, response []byte) bool {
	return len(response) >= 12 && response[0] == query[0] && response[1] == query[1] && response[2]&0x80 != 0
}
func (h *vpnFlowHandler) forwardDNS(query []byte, source, destination M.Socksaddr, writer N.PacketWriter) {
	parent := h.ctx
	if parent == nil {
		parent = context.Background()
	}
	if parent.Err() != nil {
		return
	}
	send := func(response []byte) error {
		if !matchingDNSResponse(query, response) {
			return errors.New("invalid DNS response")
		}
		packet := buf.NewSize(len(response))
		_, _ = packet.Write(response)
		// Return the virtual DNS address originally queried by Android, including IPv6.
		if err := writer.WritePacket(packet, destination); err != nil {
			return err
		}
		h.metricsOrCurrent().up.Add(int64(len(query)))
		h.metricsOrCurrent().down.Add(int64(len(response)))
		return nil
	}
	if h.udp != nil {
		assoc, err := h.udp.OpenUDPAssociation("1.1.1.1:53")
		if err == nil {
			ctx, cancel := context.WithTimeout(parent, 2*time.Second)
			if err = assoc.WriteTo(query, "1.1.1.1:53"); err == nil {
				response, readErr := assoc.Read(ctx)
				if readErr == nil && send(response.Payload) == nil {
					cancel()
					assoc.Close()
					return
				}
			}
			cancel()
			assoc.Close()
		}
	}
	response, err := dnsOverTCP(parent, h.tcp, query)
	if err != nil {
		h.recordError("DNS 经节点解析", err)
		return
	}
	if err = send(response); err != nil {
		h.recordError("DNS 回复", err)
	}
}

func dnsOverTCP(parent context.Context, session tcpBackend, query []byte) ([]byte, error) {
	if len(query) == 0 || len(query) > 65535 {
		return nil, errors.New("invalid DNS packet size")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
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
