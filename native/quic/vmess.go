package quictransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
)

// VMessConfig supports VMess TCP with optional verified TLS. WebSocket, gRPC,
// HTTP obfuscation, fingerprint impersonation and UDP are not included here.
type VMessConfig struct {
	Address      string
	ServerName   string
	UserID       string
	Security     string
	AlterID      int
	TLS          bool
	Timeout      time.Duration
	Network      Network
	TrustedCAPEM string
}

type VMessClient struct {
	serverHost string
	serverPort string
	client     *vmess.Client
	tlsConfig  *tls.Config
	tlsEnabled bool
	timeout    time.Duration
	network    Network
}

func NewVMessClient(cfg VMessConfig) (*VMessClient, error) {
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid VMess server address")
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
		tlsConfig = &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12}
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
	client, err := vmess.NewClient(cfg.UserID, security, cfg.AlterID)
	if err != nil {
		return nil, fmt.Errorf("VMess client setup: %w", err)
	}
	return &VMessClient{
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
	stream, err := c.client.DialConn(conn, M.ParseSocksaddr(net.JoinHostPort(destination, fmt.Sprint(port))))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("VMess request: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return stream, nil
}

func (c *VMessClient) Close() error { return nil }
