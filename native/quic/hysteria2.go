package quictransport

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// Hysteria2Session owns an authenticated HTTP/3 control transport and a QUIC
// connection. Android's optional native build bridges this to its local proxy.
type Hysteria2Session struct {
	Transport  *Transport
	http3      *http3.Transport
	UDPEnabled bool
	udpMu      sync.Mutex
	udpRoutes  map[uint32]chan UDPMessage
	udpOnce    sync.Once
}

type Hysteria2Config struct {
	Address    string
	ServerName string
	Password   string
	Timeout    time.Duration
	// Network is required when used behind an Android TUN interface.
	Network Network
	// TrustedCAPEM adds a supplied CA certificate without weakening hostname checks.
	TrustedCAPEM string
	// CertificateSHA256 pins the leaf certificate's SHA-256 fingerprint if present.
	CertificateSHA256 string
	// AllowUnverifiedTLS is permitted only after an explicit Android one-time warning.
	// Prefer TrustedCAPEM or CertificateSHA256; this alone is vulnerable to MITM.
	AllowUnverifiedTLS bool
}

func DialHysteria2(ctx context.Context, cfg Hysteria2Config) (*Hysteria2Session, error) {
	if cfg.Password == "" {
		return nil, errors.New("Hysteria 2 password required")
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return nil, errors.New("invalid Hysteria 2 address")
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return nil, errors.New("invalid Hysteria 2 port")
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	tlsConfig, err := newHysteria2TLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	qc := &quic.Config{KeepAlivePeriod: 15 * time.Second, MaxIdleTimeout: 60 * time.Second, EnableDatagrams: true}
	var conn *quic.Conn
	var packet net.PacketConn
	if cfg.Network != nil {
		var remote *net.UDPAddr
		packet, remote, err = protectedPacket(ctx, cfg.Address, cfg.Network)
		if err != nil {
			return nil, err
		}
		conn, err = quic.DialEarly(ctx, packet, remote, tlsConfig, qc)
	} else {
		conn, err = quic.DialAddrEarly(ctx, cfg.Address, tlsConfig, qc)
	}
	if err != nil {
		if packet != nil {
			_ = packet.Close()
		}
		return nil, fmt.Errorf("Hysteria 2 QUIC handshake: %w", err)
	}
	transport := &Transport{connection: conn, packet: packet}
	h3 := &http3.Transport{
		TLSClientConfig: tlsConfig,
		Dial: func(context.Context, string, *tls.Config, *quic.Config) (*quic.Conn, error) {
			return conn, nil
		},
	}
	session := &Hysteria2Session{Transport: transport, http3: h3}
	req, err := AuthenticationRequest(ctx, cfg.ServerName, cfg.Password)
	if err != nil {
		session.Close()
		return nil, err
	}
	resp, err := h3.RoundTrip(req)
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("Hysteria 2 HTTP/3 authentication: %w", err)
	}
	udpEnabled, authErr := Hysteria2UDPFromResponse(resp)
	if err = authErr; err != nil {
		session.Close()
		return nil, err
	}
	session.UDPEnabled = udpEnabled
	return session, nil
}

// AuthenticationRequest builds a protocol-specific HTTP/3 authentication request.
// Caller must send it over the same QUIC connection used for proxy streams.
func AuthenticationRequest(ctx context.Context, serverName, password string) (*http.Request, error) {
	if password == "" {
		return nil, errors.New("Hysteria 2 password required")
	}
	if serverName == "" || strings.ContainsAny(serverName, "/\\\r\n") {
		return nil, errors.New("invalid server name")
	}
	u := &url.URL{Scheme: "https", Host: "hysteria", Path: "/auth"}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Hysteria-Auth", password)
	req.Header.Set("Hysteria-CC-RX", "0")
	padding := make([]byte, 192)
	if _, err := rand.Read(padding); err != nil {
		return nil, err
	}
	req.Header.Set("Hysteria-Padding", base64.RawURLEncoding.EncodeToString(padding))
	return req, nil
}

func CheckAuthenticationResponse(resp *http.Response) error {
	_, err := Hysteria2UDPFromResponse(resp)
	return err
}

// Hysteria2UDPFromResponse checks protocol authentication and server UDP support.
func Hysteria2UDPFromResponse(resp *http.Response) (bool, error) {
	if resp == nil {
		return false, errors.New("missing Hysteria 2 authentication response")
	}
	// HY2 authentication is decided by the HTTP/3 status, not a response body.
	// Reading to EOF can block indefinitely if a server keeps the stream open.
	// Close the response body immediately without blocking on a drain.
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != 233 {
		return false, fmt.Errorf("Hysteria 2 authentication rejected (HTTP %d)", resp.StatusCode)
	}
	return strings.EqualFold(strings.TrimSpace(resp.Header.Get("Hysteria-UDP")), "true"), nil
}

func (s *Hysteria2Session) Close() error {
	if s == nil {
		return nil
	}
	if s.http3 != nil {
		s.http3.Close()
	}
	if s.Transport != nil {
		return s.Transport.Close()
	}
	return nil
}
