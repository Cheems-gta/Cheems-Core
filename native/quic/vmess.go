package quictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

// VMessConfig supports VMess TCP and per-destination UDP packet streams with
// optional verified TLS. WebSocket, gRPC, HTTP obfuscation and client TLS
// fingerprint impersonation are not included here.
type VMessConfig struct {
	GRPC               *GRPCConfig
	WebSocket          *WebSocketConfig
	Address            string
	ServerName         string
	UserID             string
	Security           string
	AlterID            int
	TLS                bool
	AllowUnverifiedTLS bool
	Timeout            time.Duration
	Network            Network
	TrustedCAPEM       string
}

type VMessClient struct {
	grpc       *GRPCConfig
	websocket  *WebSocketConfig
	serverHost string
	serverPort string
	client     *vmess.Client
	tlsConfig  *tls.Config
	tlsEnabled bool
	timeout    time.Duration
	network    Network
}

func NewVMessClient(cfg VMessConfig) (*VMessClient, error) {
	if cfg.GRPC != nil {
		if cfg.WebSocket != nil {
			return nil, errors.New("gRPC and WebSocket are mutually exclusive")
		}
		if e := cfg.GRPC.validate(); e != nil {
			return nil, e
		}
	}
	if cfg.WebSocket != nil {
		if e := cfg.WebSocket.validate(); e != nil {
			return nil, e
		}
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid VMess server address")
	}
	if cfg.WebSocket != nil {
		ws := *cfg.WebSocket
		if ws.Host == "" {
			ws.Host = cfg.Address
		}
		cfg.WebSocket = &ws
	}
	if _, err = parseVLESSUUID(cfg.UserID); err != nil {
		return nil, fmt.Errorf("invalid VMess user ID: %w", err)
	}
	if cfg.AlterID < 0 || cfg.AlterID > 65535 {
		return nil, errors.New("VMess alter ID must be between 0 and 65535")
	}
	if cfg.Network == nil {
		return nil, errors.New("protected physical network callback required")
	}
	security := strings.ToLower(strings.TrimSpace(cfg.Security))
	if security == "" {
		security = "auto"
	}
	switch security {
	case "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305":
	default:
		return nil, fmt.Errorf("unsupported VMess security method %q", security)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	var tlsConfig *tls.Config
	if cfg.TLS {
		if cfg.ServerName == "" {
			cfg.ServerName = host
		}
		if cfg.ServerName == "" || strings.ContainsAny(cfg.ServerName, "/\\\r\n") {
			return nil, errors.New("invalid VMess TLS server name")
		}
		if len(cfg.TrustedCAPEM) > 2*1024*1024 {
			return nil, errors.New("combined platform and custom CA bundle exceeds 2 MiB")
		}
		tlsConfig = &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.AllowUnverifiedTLS}
		if strings.TrimSpace(cfg.TrustedCAPEM) != "" {
			roots, poolErr := x509.SystemCertPool()
			if poolErr != nil || roots == nil {
				roots = x509.NewCertPool()
			}
			if !roots.AppendCertsFromPEM([]byte(cfg.TrustedCAPEM)) {
				return nil, errors.New("VMess trusted CA bundle is not valid PEM")
			}
			tlsConfig.RootCAs = roots
		}
	}
	if cfg.GRPC != nil {
		if !cfg.TLS {
			return nil, errors.New("gRPC currently requires TLS")
		}
		tlsConfig.NextProtos = []string{"h2"}
	}
	client, err := vmess.NewClient(cfg.UserID, security, cfg.AlterID)
	if err != nil {
		return nil, fmt.Errorf("VMess client setup: %w", err)
	}
	return &VMessClient{
		grpc:       cfg.GRPC,
		websocket:  cfg.WebSocket,
		serverHost: host,
		serverPort: port,
		client:     client,
		tlsConfig:  tlsConfig,
		tlsEnabled: cfg.TLS,
		timeout:    cfg.Timeout,
		network:    cfg.Network,
	}, nil
}

func (c *VMessClient) OpenTCP(ctx context.Context, destination string, port int) (io.ReadWriteCloser, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("VMess client is closed")
	}
	if destination == "" || port < 1 || port > 65535 {
		return nil, errors.New("invalid VMess destination")
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	conn, err := c.dialUpstream(ctx)
	if err != nil {
		return nil, err
	}
	stream, err := c.client.DialConn(conn, M.ParseSocksaddr(net.JoinHostPort(destination, strconv.Itoa(port))))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("VMess request: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return stream, nil
}

func (c *VMessClient) dialUpstream(ctx context.Context) (net.Conn, error) {
	resolved := c.serverHost
	ip := net.ParseIP(resolved)
	if ip == nil {
		value, err := c.network.Resolve(resolved)
		if err != nil {
			return nil, fmt.Errorf("physical network DNS: %w", err)
		}
		ip = net.ParseIP(value)
		if ip == nil {
			return nil, errors.New("physical network resolver returned a non-IP address")
		}
		resolved = value
	}
	family := "tcp6"
	if ip.To4() != nil {
		family = "tcp4"
	}
	dialer := net.Dialer{Timeout: c.timeout, Control: func(_, _ string, raw syscall.RawConn) error {
		var protectErr error
		if err := raw.Control(func(fd uintptr) {
			if !c.network.Protect(int64(fd)) {
				protectErr = errors.New("VPN socket protection or physical-network binding rejected")
			}
		}); err != nil {
			return err
		}
		return protectErr
	}}
	conn, err := dialer.DialContext(ctx, family, net.JoinHostPort(resolved, c.serverPort))
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if c.tlsEnabled {
		tlsConn := tls.Client(conn, c.tlsConfig.Clone())
		if err = tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("VMess TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	if c.grpc != nil {
		return wrapGRPC(conn, *c.grpc)
	}
	if c.websocket != nil {
		return wrapWebSocket(ctx, conn, *c.websocket)
	}
	return conn, nil
}

// OpenUDPAssociation creates one VMess UDP command stream pinned to a single
// destination, as required by the VMess packet transport.
func (c *VMessClient) OpenUDPAssociation(destination string) (*VMessUDPAssociation, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("VMess client is closed")
	}
	host, portText, err := net.SplitHostPort(destination)
	if err != nil || host == "" {
		return nil, errors.New("invalid VMess UDP destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid VMess UDP destination port")
	}
	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()
	conn, err := c.dialUpstream(ctx)
	if err != nil {
		return nil, err
	}
	packet, err := c.client.DialPacketConn(conn, M.ParseSocksaddr(destination))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("VMess UDP request: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return &VMessUDPAssociation{packet: packet, destination: destination}, nil
}

type VMessUDPAssociation struct {
	packet      net.Conn
	destination string
}

func (a *VMessUDPAssociation) WriteTo(payload []byte, address string) error {
	if a == nil || a.packet == nil {
		return errors.New("VMess UDP association is closed")
	}
	if address != a.destination {
		return errors.New("VMess UDP association destination changed")
	}
	_, err := a.packet.Write(payload)
	return err
}

func (a *VMessUDPAssociation) Read(ctx context.Context) (UDPMessage, error) {
	if a == nil || a.packet == nil {
		return UDPMessage{}, errors.New("VMess UDP association is closed")
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = a.packet.SetReadDeadline(deadline)
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = a.packet.SetReadDeadline(time.Now()); close(callbackDone) })
	buffer := make([]byte, 65535)
	n, err := a.packet.Read(buffer)
	if !stop() {
		<-callbackDone
	}
	_ = a.packet.SetReadDeadline(time.Time{})
	if ctx.Err() != nil {
		return UDPMessage{}, ctx.Err()
	}
	if err != nil {
		return UDPMessage{}, err
	}
	return UDPMessage{Address: a.destination, Payload: append([]byte(nil), buffer[:n]...)}, nil
}

func (a *VMessUDPAssociation) Close() error {
	if a == nil || a.packet == nil {
		return nil
	}
	return a.packet.Close()
}

func (c *VMessClient) Close() error { return nil }
