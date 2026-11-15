package quictransport

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
)

// AnyTLSConfig contains only standard TCP/TLS AnyTLS settings. Transport
// variants such as WebSocket are rejected by the Android importer separately.
type AnyTLSConfig struct {
	Address            string
	ServerName         string
	Password           string
	Fingerprint        string
	ALPN               []string
	Timeout            time.Duration
	Network            Network
	TrustedCAPEM       string
	CertificateSHA256  string
	AllowUnverifiedTLS bool
}

// AnyTLSClient owns the protocol client's multiplexed TLS sessions.
type AnyTLSClient struct{ client *anytls.Client }

func NewAnyTLSClient(ctx context.Context, cfg AnyTLSConfig) (*AnyTLSClient, error) {
	if cfg.Password == "" {
		return nil, errors.New("AnyTLS password required")
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid AnyTLS address")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if len(cfg.TrustedCAPEM) > 2*1024*1024 {
		return nil, errors.New("combined platform and custom CA bundle exceeds 2 MiB")
	}
	if _, err := anyTLSHelloID(cfg.Fingerprint); err != nil {
		return nil, err
	}
	for _, protocol := range cfg.ALPN {
		if len(protocol) == 0 || len(protocol) > 255 || strings.ContainsAny(protocol, "\r\n") {
			return nil, errors.New("invalid AnyTLS ALPN protocol")
		}
	}
	tlsConfig, err := newAnyTLSTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	dialOut := func(dialCtx context.Context) (net.Conn, error) {
		if cfg.Network == nil {
			return nil, errors.New("protected physical network callback required")
		}
		resolved := host
		ip := net.ParseIP(host)
		if ip == nil {
			resolvedHost, resolveErr := cfg.Network.Resolve(host)
			if resolveErr != nil {
				return nil, fmt.Errorf("physical network DNS: %w", resolveErr)
			}
			resolved = resolvedHost
			ip = net.ParseIP(resolved)
			if ip == nil {
				return nil, errors.New("physical network resolver returned a non-IP address")
			}
		}
		family := "tcp6"
		if ip.To4() != nil {
			family = "tcp4"
		}
		dialer := net.Dialer{Timeout: cfg.Timeout, Control: func(_, _ string, raw syscall.RawConn) error {
			var protectErr error
			if e := raw.Control(func(fd uintptr) {
				if !cfg.Network.Protect(int64(fd)) {
					protectErr = errors.New("VPN socket protection or physical-network binding rejected")
				}
			}); e != nil {
				return e
			}
			return protectErr
		}}
		conn, dialErr := dialer.DialContext(dialCtx, family, net.JoinHostPort(resolved, port))
		if dialErr != nil {
			return nil, dialErr
		}
		tlsConn, helloErr := anyTLSClientConn(conn, tlsConfig.Clone(), cfg.Fingerprint)
		if helloErr != nil {
			_ = conn.Close()
			return nil, helloErr
		}
		handshakeCtx, cancel := context.WithTimeout(dialCtx, cfg.Timeout)
		defer cancel()
		if handshakeErr := tlsConn.HandshakeContext(handshakeCtx); handshakeErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("AnyTLS TLS handshake: %w", handshakeErr)
		}
		return tlsConn, nil
	}
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{
		Password:                 cfg.Password,
		IdleSessionCheckInterval: 30 * time.Second,
		IdleSessionTimeout:       2 * time.Minute,
		MinIdleSession:           0,
		DisableReuse:             false,
		DialOut:                  dialOut,
		Logger:                   logger.NOP(),
	})
	if err != nil {
		return nil, err
	}
	return &AnyTLSClient{client: client}, nil
}

func newAnyTLSTLSConfig(cfg AnyTLSConfig) (*tls.Config, error) {
	if cfg.ServerName == "" || strings.ContainsAny(cfg.ServerName, "/\\\r\n") {
		return nil, errors.New("invalid AnyTLS server name")
	}
	config := &tls.Config{ServerName: cfg.ServerName, MinVersion: tls.VersionTLS12, NextProtos: append([]string(nil), cfg.ALPN...)}
	if strings.TrimSpace(cfg.TrustedCAPEM) != "" {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM([]byte(cfg.TrustedCAPEM)) {
			return nil, errors.New("AnyTLS trusted CA bundle is not valid PEM")
		}
		config.RootCAs = roots
	}
	var pin []byte
	if fingerprint := strings.TrimSpace(cfg.CertificateSHA256); fingerprint != "" {
		fingerprint = strings.NewReplacer(":", "", " ", "").Replace(fingerprint)
		decoded, err := hex.DecodeString(fingerprint)
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("invalid AnyTLS certificate SHA-256 fingerprint")
		}
		pin = decoded
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("AnyTLS certificate pin: server presented no certificate")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pin) != 1 {
				return errors.New("AnyTLS certificate pin mismatch")
			}
			return nil
		}
	}
	if cfg.AllowUnverifiedTLS {
		config.InsecureSkipVerify = true
	}
	return config, nil
}

func (c *AnyTLSClient) OpenTCP(ctx context.Context, host string, port int) (io.ReadWriteCloser, error) {
	if c == nil || c.client == nil {
		return nil, errors.New("AnyTLS client is closed")
	}
	if port < 1 || port > 65535 || host == "" {
		return nil, errors.New("invalid AnyTLS destination")
	}
	return c.client.CreateProxy(ctx, M.ParseSocksaddr(net.JoinHostPort(host, fmt.Sprint(port))))
}

func (c *AnyTLSClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}
