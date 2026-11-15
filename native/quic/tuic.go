package quictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/sagernet/sing-quic/tuic"
	M "github.com/sagernet/sing/common/metadata"
	T "github.com/sagernet/sing/common/tls"
)

// TUICConfig targets TUIC v5 with verified TLS and no 0-RTT.
type TUICConfig struct {
	Address, ServerName, UUID, Password, TrustedCAPEM, CongestionControl string
	ALPN                                                                 []string
	UDPStream                                                            bool
	Network                                                              Network
}
type TUICClient struct {
	client *tuic.Client
	cancel context.CancelFunc
}

func NewTUICClient(cfg TUICConfig) (*TUICClient, error) {
	host, p, e := net.SplitHostPort(cfg.Address)
	if e != nil || host == "" {
		return nil, errors.New("invalid TUIC address")
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid TUIC port")
	}
	id, e := parseVLESSUUID(cfg.UUID)
	if e != nil {
		return nil, e
	}
	if cfg.Password == "" || cfg.Network == nil {
		return nil, errors.New("TUIC password and protected network required")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if len(cfg.ALPN) == 0 {
		cfg.ALPN = []string{"h3"}
	}
	tc := &tls.Config{ServerName: cfg.ServerName, NextProtos: cfg.ALPN, MinVersion: tls.VersionTLS13}
	if len(cfg.TrustedCAPEM) > 2*1024*1024 {
		return nil, errors.New("TUIC CA bundle exceeds 2 MiB")
	}
	if cfg.TrustedCAPEM != "" {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(cfg.TrustedCAPEM)) {
			return nil, errors.New("invalid TUIC CA PEM")
		}
		tc.RootCAs = roots
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, e := tuic.NewClient(tuic.ClientOptions{Context: ctx, Dialer: tuicProtectedDialer{cfg.Network}, ServerAddress: M.ParseSocksaddr(cfg.Address), TLSConfig: &tuicTLSConfig{tc}, UUID: id, Password: cfg.Password, CongestionControl: cfg.CongestionControl, UDPStream: cfg.UDPStream})
	if e != nil {
		cancel()
		return nil, e
	}
	return &TUICClient{c, cancel}, nil
}
func (c *TUICClient) OpenTCP(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	if host == "" || port < 1 || port > 65535 {
		return nil, errors.New("invalid TUIC destination")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.client.DialConn(ctx, M.ParseSocksaddr(net.JoinHostPort(host, strconv.Itoa(port))))
}
func (c *TUICClient) OpenUDPAssociation() (*TUICUDPAssociation, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, e := c.client.ListenPacket(ctx)
	if e != nil {
		return nil, e
	}
	return &TUICUDPAssociation{p}, nil
}
func (c *TUICClient) Close() error { c.cancel(); return c.client.CloseWithError(net.ErrClosed) }

type TUICUDPAssociation struct{ packet net.PacketConn }

func (a *TUICUDPAssociation) WriteTo(p []byte, address string) error {
	host, port, e := net.SplitHostPort(address)
	if e != nil || host == "" {
		return errors.New("invalid TUIC UDP destination")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 {
		return errors.New("invalid TUIC UDP port")
	}
	_, e = a.packet.WriteTo(p, M.ParseSocksaddr(address))
	return e
}
func (a *TUICUDPAssociation) Read(ctx context.Context) (UDPMessage, error) {
	if d, ok := ctx.Deadline(); ok {
		_ = a.packet.SetReadDeadline(d)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = a.packet.SetReadDeadline(time.Now()); close(done) })
	b := make([]byte, 65535)
	n, addr, e := a.packet.ReadFrom(b)
	if !stop() {
		<-done
	}
	_ = a.packet.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		return UDPMessage{}, ctx.Err()
	}
	if e != nil {
		return UDPMessage{}, e
	}
	return UDPMessage{Address: addr.String(), Payload: append([]byte(nil), b[:n]...)}, nil
}
func (a *TUICUDPAssociation) Close() error { return a.packet.Close() }

type tuicProtectedDialer struct{ network Network }

func (d tuicProtectedDialer) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	ip := net.ParseIP(dst.AddrString())
	if ip == nil {
		r, e := d.network.Resolve(dst.AddrString())
		if e != nil {
			return nil, e
		}
		ip = net.ParseIP(r)
		if ip == nil {
			return nil, errors.New("physical DNS returned non-IP")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var protectErr error
		e := raw.Control(func(fd uintptr) {
			if !d.network.Protect(int64(fd)) {
				protectErr = errors.New("VPN socket protection rejected")
			}
		})
		if e != nil {
			return e
		}
		return protectErr
	}}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(dst.Port))))
}
func (d tuicProtectedDialer) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	p, _, e := protectedPacket(ctx, dst.String(), d.network)
	return p, e
}

type tuicTLSConfig struct{ config *tls.Config }

func (c *tuicTLSConfig) ServerName() string                   { return c.config.ServerName }
func (c *tuicTLSConfig) SetServerName(s string)               { c.config.ServerName = s }
func (c *tuicTLSConfig) NextProtos() []string                 { return c.config.NextProtos }
func (c *tuicTLSConfig) SetNextProtos(p []string)             { c.config.NextProtos = p }
func (c *tuicTLSConfig) HandshakeTimeout() time.Duration      { return 10 * time.Second }
func (c *tuicTLSConfig) SetHandshakeTimeout(time.Duration)    {}
func (c *tuicTLSConfig) STDConfig() (*tls.Config, error)      { return c.config, nil }
func (c *tuicTLSConfig) Client(conn net.Conn) (T.Conn, error) { return tls.Client(conn, c.config), nil }
func (c *tuicTLSConfig) Clone() T.Config                      { return &tuicTLSConfig{c.config.Clone()} }
func (c *tuicTLSConfig) Start() error                         { return nil }
func (c *tuicTLSConfig) Close() error                         { return nil }
func (c *tuicTLSConfig) Server(conn net.Conn) (T.Conn, error) { return tls.Server(conn, c.config), nil }
